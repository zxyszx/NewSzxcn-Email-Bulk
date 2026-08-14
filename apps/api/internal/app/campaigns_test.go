package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCampaignMultiSenderQueuesOneRecipientAndRetriesFailures(t *testing.T) {
	a := newTestApp(t)
	stopTestWorkers(a)
	now := time.Date(2026, 8, 14, 8, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }
	a.updateConfig(func(cfg *Config) {
		cfg.SMTPHost = "127.0.0.1"
		cfg.SMTPPort = "1"
		cfg.PublicBaseURL = "https://mail.example.test"
	})

	ts := httptest.NewServer(a.Router())
	defer ts.Close()
	admin := &testClient{t: t, server: ts}
	if code := admin.do("POST", "/api/auth/login", map[string]string{"email": "admin@lanqin.local", "password": "ChangeMe123!"}, nil); code != http.StatusOK {
		t.Fatalf("login code=%d", code)
	}
	user, primary := defaultAdminUserAndMailbox(t, a)
	secondary := createTestMailbox(t, admin, primary.DomainID, "campaign", "Campaign Sender", "Password123!", map[string]any{"userId": user.ID})

	if code := admin.do("POST", "/api/admin/campaign-suppressions", map[string]string{"email": "blocked@example.test", "reason": "opted out"}, nil); code != http.StatusCreated {
		t.Fatalf("create suppression code=%d", code)
	}
	payload := map[string]any{
		"mailboxIds":       []string{primary.ID, secondary.ID},
		"name":             "August notice",
		"subject":          "Account update",
		"text":             "Hello from the campaign",
		"html":             "<p>Hello from the campaign</p>",
		"ratePerMinute":    300,
		"consentConfirmed": true,
		"recipients": []map[string]string{
			{"email": "first@example.test", "name": "First"},
			{"email": "SECOND@example.test", "name": "Second"},
			{"email": "first@example.test", "name": "Duplicate"},
			{"email": "blocked@example.test", "name": "Blocked"},
		},
	}
	var campaign Campaign
	if code := admin.do("POST", "/api/admin/campaigns", payload, &campaign); code != http.StatusCreated {
		t.Fatalf("create campaign code=%d campaign=%+v", code, campaign)
	}
	if campaign.TotalCount != 3 || campaign.PendingCount != 2 || campaign.SuppressedCount != 1 || campaign.SenderCount != 2 {
		t.Fatalf("unexpected campaign counts: %+v", campaign)
	}
	if code := admin.do("POST", "/api/admin/campaigns/"+campaign.ID+"/start", nil, &campaign); code != http.StatusOK || campaign.Status != campaignStatusRunning {
		t.Fatalf("start campaign code=%d campaign=%+v", code, campaign)
	}
	if err := a.processCampaigns(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if err := a.processCampaigns(context.Background()); err != nil {
		t.Fatal(err)
	}

	rows, err := a.db.Query(`SELECT mailbox_id,recipients_json,mime_base64 FROM send_queue WHERE source=? ORDER BY created_at,id`, sendSourceCampaign)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	mailboxCounts := map[string]int{}
	queueCount := 0
	for rows.Next() {
		var mailboxID, recipientsJSON, mimeBase64 string
		if err := rows.Scan(&mailboxID, &recipientsJSON, &mimeBase64); err != nil {
			t.Fatal(err)
		}
		recipients := jsonDecodeSlice(recipientsJSON)
		if len(recipients) != 1 {
			t.Fatalf("queue item exposed multiple recipients: %q", recipientsJSON)
		}
		mimeBytes, err := base64.StdEncoding.DecodeString(mimeBase64)
		if err != nil {
			t.Fatal(err)
		}
		mimeText := string(mimeBytes)
		for _, header := range []string{"List-Unsubscribe: <https://mail.example.test/api/unsubscribe?token=", "List-Unsubscribe-Post: List-Unsubscribe=One-Click", "Precedence: bulk"} {
			if !strings.Contains(mimeText, header) {
				t.Fatalf("campaign MIME missing %q: %s", header, mimeText)
			}
		}
		mailboxCounts[mailboxID]++
		queueCount++
	}
	if queueCount != 2 || mailboxCounts[primary.ID] != 1 || mailboxCounts[secondary.ID] != 1 {
		t.Fatalf("queue distribution count=%d by mailbox=%v", queueCount, mailboxCounts)
	}

	if _, err := a.db.Exec(`UPDATE send_queue SET max_attempts=1 WHERE source=?`, sendSourceCampaign); err != nil {
		t.Fatal(err)
	}
	if err := a.processDueSendQueue(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.processCampaigns(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.db.QueryRow(`SELECT status,failed_count FROM campaigns WHERE id=?`, campaign.ID).Scan(&campaign.Status, &campaign.FailedCount); err != nil {
		t.Fatal(err)
	}
	if campaign.Status != campaignStatusCompleted || campaign.FailedCount != 2 {
		t.Fatalf("campaign did not finish with failures: %+v", campaign)
	}
	var retried struct {
		Retried int64 `json:"retried"`
	}
	if code := admin.do("POST", "/api/admin/campaigns/"+campaign.ID+"/retry-failed", map[string]any{"recipientIds": []string{}}, &retried); code != http.StatusOK || retried.Retried != 2 {
		t.Fatalf("retry failed recipients code=%d result=%+v", code, retried)
	}
}

func TestCampaignDistributesOnlySendableRecipientsAcrossSenders(t *testing.T) {
	a := newTestApp(t)
	stopTestWorkers(a)
	a.updateConfig(func(cfg *Config) {
		cfg.SMTPHost = "127.0.0.1"
		cfg.SMTPPort = "1"
		cfg.PublicBaseURL = "https://mail.example.test"
	})

	ts := httptest.NewServer(a.Router())
	defer ts.Close()
	admin := &testClient{t: t, server: ts}
	if code := admin.do("POST", "/api/auth/login", map[string]string{"email": "admin@lanqin.local", "password": "ChangeMe123!"}, nil); code != http.StatusOK {
		t.Fatalf("login code=%d", code)
	}
	user, primary := defaultAdminUserAndMailbox(t, a)
	secondary := createTestMailbox(t, admin, primary.DomainID, "campaign-two", "Campaign Two", "Password123!", map[string]any{"userId": user.ID})
	tertiary := createTestMailbox(t, admin, primary.DomainID, "campaign-three", "Campaign Three", "Password123!", map[string]any{"userId": user.ID})
	if code := admin.do("POST", "/api/admin/campaign-suppressions", map[string]string{"email": "blocked-first@example.test", "reason": "opted out"}, nil); code != http.StatusCreated {
		t.Fatalf("create suppression code=%d", code)
	}

	recipients := []map[string]string{{"email": "blocked-first@example.test"}}
	for index := 1; index <= 7; index++ {
		recipients = append(recipients, map[string]string{"email": fmt.Sprintf("person-%d@example.test", index)})
	}
	var created Campaign
	if code := admin.do("POST", "/api/admin/campaigns", map[string]any{
		"mailboxIds":       []string{primary.ID, secondary.ID, tertiary.ID},
		"name":             "Uneven distribution",
		"subject":          "Distribution test",
		"text":             "Hello",
		"ratePerMinute":    300,
		"consentConfirmed": true,
		"recipients":       recipients,
	}, &created); code != http.StatusCreated {
		t.Fatalf("create campaign code=%d campaign=%+v", code, created)
	}
	var campaign Campaign
	if code := admin.do("GET", "/api/admin/campaigns/"+created.ID, nil, &campaign); code != http.StatusOK {
		t.Fatalf("get campaign code=%d", code)
	}
	if campaign.TotalCount != 8 || campaign.PendingCount != 7 || campaign.SuppressedCount != 1 {
		t.Fatalf("unexpected campaign counts: %+v", campaign)
	}
	counts := map[string]int{}
	for _, sender := range campaign.Senders {
		counts[sender.MailboxID] = sender.Count
	}
	if counts[primary.ID] != 3 || counts[secondary.ID] != 2 || counts[tertiary.ID] != 2 {
		t.Fatalf("sender distribution=%v, want 3/2/2", counts)
	}
}

func TestCampaignPauseResumeControlsDispatch(t *testing.T) {
	a := newTestApp(t)
	stopTestWorkers(a)
	now := time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }
	a.updateConfig(func(cfg *Config) {
		cfg.SMTPHost = "127.0.0.1"
		cfg.SMTPPort = "1"
		cfg.PublicBaseURL = "https://mail.example.test"
	})

	ts := httptest.NewServer(a.Router())
	defer ts.Close()
	admin := &testClient{t: t, server: ts}
	if code := admin.do("POST", "/api/auth/login", map[string]string{"email": "admin@lanqin.local", "password": "ChangeMe123!"}, nil); code != http.StatusOK {
		t.Fatalf("login code=%d", code)
	}
	_, mailbox := defaultAdminUserAndMailbox(t, a)
	var campaign Campaign
	if code := admin.do("POST", "/api/admin/campaigns", map[string]any{
		"mailboxIds":       []string{mailbox.ID},
		"name":             "Pause and resume",
		"subject":          "Pause test",
		"text":             "Hello",
		"ratePerMinute":    60,
		"consentConfirmed": true,
		"recipients": []map[string]string{
			{"email": "one@example.test"},
			{"email": "two@example.test"},
		},
	}, &campaign); code != http.StatusCreated {
		t.Fatalf("create campaign code=%d", code)
	}
	if code := admin.do("POST", "/api/admin/campaigns/"+campaign.ID+"/start", nil, &campaign); code != http.StatusOK {
		t.Fatalf("start campaign code=%d", code)
	}
	if code := admin.do("POST", "/api/admin/campaigns/"+campaign.ID+"/pause", nil, &campaign); code != http.StatusOK || campaign.Status != campaignStatusPaused {
		t.Fatalf("pause campaign code=%d campaign=%+v", code, campaign)
	}
	if err := a.processCampaigns(context.Background()); err != nil {
		t.Fatal(err)
	}
	var queueCount int
	if err := a.db.QueryRow(`SELECT COUNT(1) FROM send_queue WHERE source=?`, sendSourceCampaign).Scan(&queueCount); err != nil {
		t.Fatal(err)
	}
	if queueCount != 0 {
		t.Fatalf("paused campaign queued %d messages", queueCount)
	}
	if code := admin.do("POST", "/api/admin/campaigns/"+campaign.ID+"/resume", nil, &campaign); code != http.StatusOK || campaign.Status != campaignStatusRunning {
		t.Fatalf("resume campaign code=%d campaign=%+v", code, campaign)
	}
	if err := a.processCampaigns(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if err := a.processCampaigns(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.db.QueryRow(`SELECT COUNT(1) FROM send_queue WHERE source=?`, sendSourceCampaign).Scan(&queueCount); err != nil {
		t.Fatal(err)
	}
	if queueCount != 2 {
		t.Fatalf("resumed campaign queued %d messages, want 2", queueCount)
	}
}

func TestCampaignRelayDeliveryAndFailureRetry(t *testing.T) {
	a := newTestApp(t)
	stopTestWorkers(a)
	now := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }
	a.updateConfig(func(cfg *Config) {
		cfg.SMTPHost = "127.0.0.1"
		cfg.SMTPPort = "1"
		cfg.PublicBaseURL = "https://mail.example.test"
	})

	ts := httptest.NewServer(a.Router())
	defer ts.Close()
	admin := &testClient{t: t, server: ts}
	if code := admin.do("POST", "/api/auth/login", map[string]string{"email": "admin@lanqin.local", "password": "ChangeMe123!"}, nil); code != http.StatusOK {
		t.Fatalf("login code=%d", code)
	}
	_, mailbox := defaultAdminUserAndMailbox(t, a)
	var campaign Campaign
	if code := admin.do("POST", "/api/admin/campaigns", map[string]any{
		"mailboxIds":       []string{mailbox.ID},
		"name":             "Relay retry",
		"subject":          "Relay test",
		"text":             "Hello through relay",
		"ratePerMinute":    300,
		"consentConfirmed": true,
		"recipients":       []map[string]string{{"email": "relay@example.test"}},
	}, &campaign); code != http.StatusCreated {
		t.Fatalf("create campaign code=%d", code)
	}
	if code := admin.do("POST", "/api/admin/campaigns/"+campaign.ID+"/start", nil, &campaign); code != http.StatusOK {
		t.Fatalf("start campaign code=%d", code)
	}
	if err := a.processCampaigns(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.processDueSendQueue(context.Background()); err != nil {
		t.Fatal(err)
	}
	var queueID, status string
	var attempts int
	if err := a.db.QueryRow(`SELECT id,status,attempt_count FROM send_queue WHERE source=?`, sendSourceCampaign).Scan(&queueID, &status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != sendQueueStatusFailed || attempts != 1 {
		t.Fatalf("initial relay status=%q attempts=%d", status, attempts)
	}

	host, port, received := startCapturingSMTP(t, 1)
	a.updateConfig(func(cfg *Config) {
		cfg.SMTPHost = host
		cfg.SMTPPort = port
	})
	now = now.Add(30 * time.Second)
	if err := a.processDueSendQueue(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-received:
		if !strings.Contains(body, "To: relay@example.test") || strings.Contains(body, "Bcc:") {
			t.Fatalf("unexpected relayed campaign body: %s", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retried campaign message was not relayed")
	}
	if err := a.processCampaigns(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.db.QueryRow(`SELECT status,attempt_count FROM send_queue WHERE id=?`, queueID).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != sendQueueStatusDelivered || attempts != 2 {
		t.Fatalf("retried relay status=%q attempts=%d", status, attempts)
	}
	if err := a.db.QueryRow(`SELECT status,delivered_count,failed_count FROM campaigns WHERE id=?`, campaign.ID).Scan(&campaign.Status, &campaign.DeliveredCount, &campaign.FailedCount); err != nil {
		t.Fatal(err)
	}
	if campaign.Status != campaignStatusCompleted || campaign.DeliveredCount != 1 || campaign.FailedCount != 0 {
		t.Fatalf("unexpected completed campaign: %+v", campaign)
	}
}

func TestCampaignUnsubscribeSuppressesPendingAndRejectsForgedToken(t *testing.T) {
	a := newTestApp(t)
	stopTestWorkers(a)
	ctx := context.Background()
	user, mailbox := defaultAdminUserAndMailbox(t, a)
	now := a.now().UTC().Format(time.RFC3339Nano)
	campaignID := newID("cmp")
	recipientID := newID("crp")
	if _, err := a.db.ExecContext(ctx, `INSERT INTO campaigns(id,user_id,mailbox_id,name,subject,body_text,body_html,status,rate_per_minute,consent_confirmed,total_count,pending_count,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, campaignID, user.ID, mailbox.ID, "Consent", "Subject", "Body", "<p>Body</p>", campaignStatusDraft, 30, 1, 1, 1, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.ExecContext(ctx, `INSERT INTO campaign_senders(campaign_id,mailbox_id,sort_order,created_at) VALUES(?,?,0,?)`, campaignID, mailbox.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.ExecContext(ctx, `INSERT INTO campaign_recipients(id,campaign_id,mailbox_id,email,name,status,created_at,updated_at) VALUES(?,?,?,?,?,'pending',?,?)`, recipientID, campaignID, mailbox.ID, "person@example.test", "Person", now, now); err != nil {
		t.Fatal(err)
	}
	token, err := a.campaignUnsubscribeToken(ctx, recipientID)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(a.Router())
	defer server.Close()
	client := &testClient{t: t, server: server}
	if code := client.do("GET", "/api/unsubscribe?token="+token+"forged", nil, nil); code != http.StatusBadRequest {
		t.Fatalf("forged unsubscribe token code=%d", code)
	}
	if code := client.do("GET", "/api/unsubscribe?token="+token, nil, nil); code != http.StatusOK {
		t.Fatalf("unsubscribe code=%d", code)
	}
	var suppressionCount int
	if err := a.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM campaign_suppressions WHERE email='person@example.test' AND source='unsubscribe'`).Scan(&suppressionCount); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := a.db.QueryRowContext(ctx, `SELECT status FROM campaign_recipients WHERE id=?`, recipientID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if suppressionCount != 1 || status != campaignRecipientSuppressed {
		t.Fatalf("suppression count=%d recipient status=%q", suppressionCount, status)
	}
}
