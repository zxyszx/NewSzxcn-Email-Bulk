package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSMTPRelayPrecedenceQuotaAndCredentialSafety(t *testing.T) {
	a := newTestApp(t)
	stopTestWorkers(a)
	a.updateConfig(func(cfg *Config) { cfg.SMTPRelaySecretKey = "relay-test-secret" })
	ts := httptest.NewServer(a.Router())
	defer ts.Close()
	admin := &testClient{t: t, server: ts}
	if code := admin.do("POST", "/api/auth/login", map[string]string{"email": "admin@lanqin.local", "password": "ChangeMe123!"}, nil); code != http.StatusOK {
		t.Fatalf("login code=%d", code)
	}
	_, mailbox := defaultAdminUserAndMailbox(t, a)
	create := func(name string, priority, minuteLimit int, domainIDs, mailboxIDs []string) SMTPRelay {
		var relay SMTPRelay
		payload := map[string]any{"name": name, "host": "127.0.0.1", "port": 2525, "username": name, "password": "super-secret-password", "tlsMode": "plain", "enabled": true, "priority": priority, "minuteLimit": minuteLimit, "dailyLimit": 1000, "domainIds": domainIDs, "mailboxIds": mailboxIDs}
		if code := admin.do("POST", "/api/admin/smtp-relays", payload, &relay); code != http.StatusCreated {
			t.Fatalf("create %s code=%d", name, code)
		}
		raw, _ := json.Marshal(relay)
		if strings.Contains(string(raw), "super-secret-password") || strings.Contains(string(raw), `"password"`) {
			t.Fatalf("relay response exposed password: %s", raw)
		}
		return relay
	}
	global := create("global", 1, 10, nil, nil)
	domain := create("domain", 50, 10, []string{mailbox.DomainID}, nil)
	mailboxRelay := create("mailbox", 100, 1, nil, []string{mailbox.ID})
	candidates, err := a.relayCandidates(context.Background(), mailbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 3 || candidates[0].ID != mailboxRelay.ID || candidates[1].ID != domain.ID || candidates[2].ID != global.ID {
		t.Fatalf("unexpected relay precedence: %+v", candidates)
	}
	now := a.now().UTC().Format(time.RFC3339Nano)
	if _, err := a.db.Exec(`INSERT INTO smtp_relay_events(id,relay_id,queue_id,event,created_at) VALUES(?,?,?,?,?)`, newID("rle"), mailboxRelay.ID, "quota-test", "reserved", now); err != nil {
		t.Fatal(err)
	}
	candidates, err = a.relayCandidates(context.Background(), mailbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 || candidates[0].ID != domain.ID {
		t.Fatalf("quota did not skip exhausted mailbox relay: %+v", candidates)
	}
}

func TestSMTPRelayFailoverDeliversThroughNextRelay(t *testing.T) {
	a := newTestApp(t)
	stopTestWorkers(a)
	a.updateConfig(func(cfg *Config) { cfg.SMTPRelaySecretKey = "relay-test-secret"; cfg.SMTPHost = "" })
	_, mailbox := defaultAdminUserAndMailbox(t, a)
	host, port, received := startCapturingSMTP(t, 1)
	insertRelay := func(name, relayHost string, relayPort, priority int) string {
		ciphertext, err := a.encryptSMTPRelayPassword("password")
		if err != nil {
			t.Fatal(err)
		}
		id, now := newID("rly"), a.now().UTC().Format(time.RFC3339Nano)
		if _, err := a.db.Exec(`INSERT INTO smtp_relays(id,name,host,port,username,password_ciphertext,tls_mode,enabled,priority,minute_limit,daily_limit,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, name, relayHost, relayPort, "", ciphertext, "plain", 1, priority, 100, 1000, now, now); err != nil {
			t.Fatal(err)
		}
		return id
	}
	failedID := insertRelay("unavailable", "127.0.0.1", 1, 1)
	portNumber, _ := strconv.Atoi(port)
	successID := insertRelay("available", host, portNumber, 2)
	mimeBytes, err := BuildMIME(MIMEMessage{From: mailbox.Address, To: []string{"recipient@example.test"}, Subject: "relay failover", Text: "hello", MessageID: "<relay-failover@example.test>", Date: a.now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	queueID, err := a.enqueueSend(context.Background(), sendQueueInput{UserID: mailbox.UserID, MailboxID: mailbox.ID, MessageID: "<relay-failover@example.test>", Source: sendSourceCampaign, MailFrom: mailbox.Address, HeaderFrom: mailbox.Address, Recipients: []string{"recipient@example.test"}, MIMEBytes: mimeBytes})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.processDueSendQueue(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("next relay did not receive message")
	}
	var status, relayID string
	if err := a.db.QueryRow(`SELECT status,relay_id FROM send_queue WHERE id=?`, queueID).Scan(&status, &relayID); err != nil {
		t.Fatal(err)
	}
	if status != sendQueueStatusDelivered || relayID != successID {
		t.Fatalf("queue status=%s relay=%s", status, relayID)
	}
	var failures int
	if err := a.db.QueryRow(`SELECT failure_count FROM smtp_relays WHERE id=?`, failedID).Scan(&failures); err != nil || failures != 1 {
		t.Fatalf("first relay failures=%d err=%v", failures, err)
	}
}

func TestSMTPRelayQuotaDelaysWithoutConsumingAttempts(t *testing.T) {
	a := newTestApp(t)
	stopTestWorkers(a)
	a.updateConfig(func(cfg *Config) { cfg.SMTPRelaySecretKey = "relay-test-secret"; cfg.SMTPHost = "" })
	_, mailbox := defaultAdminUserAndMailbox(t, a)
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }
	ciphertext, err := a.encryptSMTPRelayPassword("password")
	if err != nil {
		t.Fatal(err)
	}
	relayID := newID("rly")
	timestamp := now.Format(time.RFC3339Nano)
	if _, err := a.db.Exec(`INSERT INTO smtp_relays(id,name,host,port,password_ciphertext,tls_mode,enabled,priority,minute_limit,daily_limit,created_at,updated_at) VALUES(?,?,?,? ,?,'plain',1,100,1,1000,?,?)`, relayID, "limited", "127.0.0.1", 1, ciphertext, timestamp, timestamp); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(`INSERT INTO smtp_relay_events(id,relay_id,queue_id,event,created_at) VALUES(?,?,?,?,?)`, newID("rle"), relayID, "already-used", "reserved", timestamp); err != nil {
		t.Fatal(err)
	}
	mimeBytes, err := BuildMIME(MIMEMessage{From: mailbox.Address, To: []string{"recipient@example.test"}, Subject: "quota", Text: "hello", MessageID: "<quota@example.test>", Date: now})
	if err != nil {
		t.Fatal(err)
	}
	queueID, err := a.enqueueSend(context.Background(), sendQueueInput{UserID: mailbox.UserID, MailboxID: mailbox.ID, MessageID: "<quota@example.test>", Source: sendSourceCampaign, MailFrom: mailbox.Address, HeaderFrom: mailbox.Address, Recipients: []string{"recipient@example.test"}, MIMEBytes: mimeBytes, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.processDueSendQueue(context.Background()); err != nil {
		t.Fatal(err)
	}
	var status, next string
	var attempts int
	if err := a.db.QueryRow(`SELECT status,attempt_count,next_attempt_at FROM send_queue WHERE id=?`, queueID).Scan(&status, &attempts, &next); err != nil {
		t.Fatal(err)
	}
	if status != sendQueueStatusQueued || attempts != 0 || !parseTime(next).After(now) {
		t.Fatalf("status=%s attempts=%d next=%s", status, attempts, next)
	}
}

func TestCampaignComplaintCallbackSuppressesAndAutoPausesIdempotently(t *testing.T) {
	a := newTestApp(t)
	stopTestWorkers(a)
	ctx := context.Background()
	user, mailbox := defaultAdminUserAndMailbox(t, a)
	now := a.now().UTC().Format(time.RFC3339Nano)
	if _, err := a.db.Exec(`UPDATE deliverability_settings SET minimum_sample=1,complaint_threshold=0.1 WHERE id='default'`); err != nil {
		t.Fatal(err)
	}
	campaignID, recipientID, queueID := newID("cmp"), newID("crp"), newID("snd")
	address := "complaint@example.test"
	if _, err := a.db.Exec(`INSERT INTO campaigns(id,user_id,mailbox_id,name,subject,status,rate_per_minute,consent_confirmed,total_count,queued_count,created_at,updated_at) VALUES(?,?,?,?,?,'running',30,1,1,1,?,?)`, campaignID, user.ID, mailbox.ID, "Complaint", "Subject", now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(`INSERT INTO campaign_recipients(id,campaign_id,mailbox_id,email,status,queue_id,created_at,updated_at) VALUES(?,?,?,?, 'queued',?,?,?)`, recipientID, campaignID, mailbox.ID, address, queueID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(`INSERT INTO send_queue(id,user_id,mailbox_id,message_id,source,mail_from,header_from,recipients_json,mime_base64,status,next_attempt_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,'delivered',?,?,?)`, queueID, user.ID, mailbox.ID, "<complaint@example.test>", sendSourceCampaign, mailbox.Address, mailbox.Address, jsonEncode([]string{address}), "", now, now, now); err != nil {
		t.Fatal(err)
	}
	event := deliveryWebhookEvent{ID: "complaint-event-1", Provider: "test", QueueID: queueID, Recipient: address, Status: "complained", Reason: "feedback loop complaint", OccurredAt: now}
	req := httptest.NewRequest(http.MethodPost, "/api/open/v1/delivery-events", nil)
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	inserted, err := a.storeDeliveryEvent(req, tx, event)
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatal("first event was not inserted")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var campaignStatus, pauseReason, recipientStatus string
	if err := a.db.QueryRow(`SELECT status,pause_reason FROM campaigns WHERE id=?`, campaignID).Scan(&campaignStatus, &pauseReason); err != nil {
		t.Fatal(err)
	}
	if err := a.db.QueryRow(`SELECT status FROM campaign_recipients WHERE id=?`, recipientID).Scan(&recipientStatus); err != nil {
		t.Fatal(err)
	}
	if campaignStatus != campaignStatusPaused || pauseReason == "" || recipientStatus != campaignRecipientSuppressed {
		t.Fatalf("status=%s reason=%q recipient=%s", campaignStatus, pauseReason, recipientStatus)
	}
	var suppressionCount int
	if err := a.db.QueryRow(`SELECT COUNT(1) FROM campaign_suppressions WHERE email=? AND source='complaint'`, address).Scan(&suppressionCount); err != nil || suppressionCount != 1 {
		t.Fatalf("suppression count=%d err=%v", suppressionCount, err)
	}
	tx, _ = a.db.BeginTx(ctx, nil)
	inserted, err = a.storeDeliveryEvent(req, tx, event)
	if err != nil {
		t.Fatal(err)
	}
	if inserted {
		t.Fatal("duplicate event was inserted")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
