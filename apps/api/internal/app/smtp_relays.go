package app

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

type SMTPRelay struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Host             string     `json:"host"`
	Port             int        `json:"port"`
	Username         string     `json:"username"`
	PasswordSet      bool       `json:"passwordSet"`
	TLSMode          string     `json:"tlsMode"`
	Enabled          bool       `json:"enabled"`
	Priority         int        `json:"priority"`
	MinuteLimit      int        `json:"minuteLimit"`
	DailyLimit       int        `json:"dailyLimit"`
	DomainIDs        []string   `json:"domainIds"`
	MailboxIDs       []string   `json:"mailboxIds"`
	FailureCount     int        `json:"failureCount"`
	CircuitOpenUntil *time.Time `json:"circuitOpenUntil,omitempty"`
	LastError        string     `json:"lastError,omitempty"`
	LastSuccessAt    *time.Time `json:"lastSuccessAt,omitempty"`
	MinuteUsed       int        `json:"minuteUsed"`
	DailyUsed        int        `json:"dailyUsed"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
}

type smtpRelayInput struct {
	Name        string   `json:"name"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	TLSMode     string   `json:"tlsMode"`
	Enabled     bool     `json:"enabled"`
	Priority    int      `json:"priority"`
	MinuteLimit int      `json:"minuteLimit"`
	DailyLimit  int      `json:"dailyLimit"`
	DomainIDs   []string `json:"domainIds"`
	MailboxIDs  []string `json:"mailboxIds"`
}

type smtpRelayRuntime struct {
	SMTPRelay
	Password    string
	specificity int
}

type smtpQueueDelayError struct {
	Until  time.Time
	Reason string
}

func (e *smtpQueueDelayError) Error() string { return e.Reason }

type DeliverabilitySettings struct {
	AutoPause               bool    `json:"autoPause"`
	ComplaintThreshold      float64 `json:"complaintThreshold"`
	BounceThreshold         float64 `json:"bounceThreshold"`
	MinimumSample           int     `json:"minimumSample"`
	CircuitFailureThreshold int     `json:"circuitFailureThreshold"`
	CircuitMinutes          int     `json:"circuitMinutes"`
	CallbackURL             string  `json:"callbackUrl"`
	CallbackConfigured      bool    `json:"callbackConfigured"`
	RelaySecretConfigured   bool    `json:"relaySecretConfigured"`
}

func (a *App) handleListSMTPRelays(w http.ResponseWriter, r *http.Request) {
	items, err := a.listSMTPRelays(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list SMTP relays")
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *App) handleCreateSMTPRelay(w http.ResponseWriter, r *http.Request) {
	var req smtpRelayInput
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, err)
		return
	}
	normalized, err := a.normalizeSMTPRelayInput(r.Context(), req)
	if err != nil {
		badRequest(w, err)
		return
	}
	if strings.TrimSpace(normalized.Password) == "" {
		badRequest(w, errors.New("中继密码不能为空"))
		return
	}
	ciphertext, err := a.encryptSMTPRelayPassword(normalized.Password)
	if err != nil {
		badRequest(w, err)
		return
	}
	now := a.now().UTC().Format(time.RFC3339Nano)
	id := newID("rly")
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO smtp_relays(id,name,host,port,username,password_ciphertext,tls_mode,enabled,priority,minute_limit,daily_limit,domain_ids_json,mailbox_ids_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, normalized.Name, normalized.Host, normalized.Port, normalized.Username, ciphertext, normalized.TLSMode, boolInt(normalized.Enabled), normalized.Priority, normalized.MinuteLimit, normalized.DailyLimit, jsonEncode(normalized.DomainIDs), jsonEncode(normalized.MailboxIDs), now, now)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create SMTP relay")
		return
	}
	item, err := a.smtpRelayByID(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load SMTP relay")
		return
	}
	respondJSON(w, http.StatusCreated, item)
}

func (a *App) handleUpdateSMTPRelay(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_, err := a.smtpRelayByID(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "SMTP relay not found")
		return
	}
	var req smtpRelayInput
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, err)
		return
	}
	normalized, err := a.normalizeSMTPRelayInput(r.Context(), req)
	if err != nil {
		badRequest(w, err)
		return
	}
	ciphertext := ""
	if strings.TrimSpace(normalized.Password) == "" {
		var stored string
		if err := a.db.QueryRowContext(r.Context(), `SELECT password_ciphertext FROM smtp_relays WHERE id=?`, id).Scan(&stored); err != nil {
			respondError(w, http.StatusNotFound, "SMTP relay not found")
			return
		}
		ciphertext = stored
	} else {
		ciphertext, err = a.encryptSMTPRelayPassword(normalized.Password)
		if err != nil {
			badRequest(w, err)
			return
		}
	}
	now := a.now().UTC().Format(time.RFC3339Nano)
	res, err := a.db.ExecContext(r.Context(), `UPDATE smtp_relays SET name=?,host=?,port=?,username=?,password_ciphertext=?,tls_mode=?,enabled=?,priority=?,minute_limit=?,daily_limit=?,domain_ids_json=?,mailbox_ids_json=?,failure_count=CASE WHEN enabled<>? THEN 0 ELSE failure_count END,circuit_open_until=CASE WHEN enabled<>? THEN NULL ELSE circuit_open_until END,updated_at=? WHERE id=?`,
		normalized.Name, normalized.Host, normalized.Port, normalized.Username, ciphertext, normalized.TLSMode, boolInt(normalized.Enabled), normalized.Priority, normalized.MinuteLimit, normalized.DailyLimit, jsonEncode(normalized.DomainIDs), jsonEncode(normalized.MailboxIDs), boolInt(normalized.Enabled), boolInt(normalized.Enabled), now, id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update SMTP relay")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		respondError(w, http.StatusNotFound, "SMTP relay not found")
		return
	}
	item, _ := a.smtpRelayByID(r.Context(), id)
	respondJSON(w, http.StatusOK, item)
}

func (a *App) handleDeleteSMTPRelay(w http.ResponseWriter, r *http.Request) {
	res, err := a.db.ExecContext(r.Context(), `DELETE FROM smtp_relays WHERE id=?`, chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete SMTP relay")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		respondError(w, http.StatusNotFound, "SMTP relay not found")
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleTestSMTPRelay(w http.ResponseWriter, r *http.Request) {
	relay, err := a.smtpRelayRuntimeByID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusNotFound, "SMTP relay not found")
		return
	}
	var req smtpTestRequest
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, err)
		return
	}
	to := normalizeEmail(req.To)
	if _, err := mail.ParseAddress(to); err != nil {
		badRequest(w, errors.New("收件邮箱无效"))
		return
	}
	from := normalizeEmail(currentUser(r).Email)
	mimeBytes, err := BuildMIME(MIMEMessage{From: from, To: []string{to}, Subject: "NewSzxcn 中继测试", Text: "这是一封 SMTP 中继测试邮件。", HTML: "<p>这是一封 SMTP 中继测试邮件。</p>", MessageID: "<" + newID("msg") + "@" + strings.SplitN(from, "@", 2)[1] + ">", Date: a.now().UTC()})
	if err != nil {
		badRequest(w, err)
		return
	}
	if err := sendSMTPWithConfig(relay.config(a.config()), from, []string{to}, mimeBytes); err != nil {
		respondError(w, http.StatusBadGateway, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *App) handleGetDeliverabilitySettings(w http.ResponseWriter, r *http.Request) {
	settings, err := a.deliverabilitySettings(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load deliverability settings")
		return
	}
	respondJSON(w, http.StatusOK, settings)
}

func (a *App) handleUpdateDeliverabilitySettings(w http.ResponseWriter, r *http.Request) {
	var req DeliverabilitySettings
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, err)
		return
	}
	if req.ComplaintThreshold < 0.01 || req.ComplaintThreshold > 10 || req.BounceThreshold < 0.1 || req.BounceThreshold > 50 || req.MinimumSample < 1 || req.MinimumSample > 100000 || req.CircuitFailureThreshold < 1 || req.CircuitFailureThreshold > 20 || req.CircuitMinutes < 1 || req.CircuitMinutes > 1440 {
		badRequest(w, errors.New("投递保护参数超出允许范围"))
		return
	}
	now := a.now().UTC().Format(time.RFC3339Nano)
	_, err := a.db.ExecContext(r.Context(), `UPDATE deliverability_settings SET auto_pause=?,complaint_threshold=?,bounce_threshold=?,minimum_sample=?,circuit_failure_threshold=?,circuit_minutes=?,updated_at=? WHERE id='default'`, boolInt(req.AutoPause), req.ComplaintThreshold, req.BounceThreshold, req.MinimumSample, req.CircuitFailureThreshold, req.CircuitMinutes, now)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update deliverability settings")
		return
	}
	settings, _ := a.deliverabilitySettings(r.Context())
	respondJSON(w, http.StatusOK, settings)
}

func (a *App) normalizeSMTPRelayInput(ctx context.Context, in smtpRelayInput) (smtpRelayInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Host = strings.TrimSpace(in.Host)
	in.Username = strings.TrimSpace(in.Username)
	in.TLSMode = strings.ToLower(strings.TrimSpace(in.TLSMode))
	if in.Name == "" || len([]rune(in.Name)) > 80 {
		return in, errors.New("中继名称不能为空且不能超过 80 个字符")
	}
	if in.Host == "" || len(in.Host) > 253 || strings.ContainsAny(in.Host, "/@\r\n\t ") || net.ParseIP(in.Host) == nil && normalizeHostname(in.Host) == "" {
		return in, errors.New("中继主机格式无效，请只填写域名或 IP")
	}
	if in.Port < 1 || in.Port > 65535 {
		return in, errors.New("中继端口必须在 1 至 65535 之间")
	}
	if in.TLSMode != "plain" && in.TLSMode != "starttls" && in.TLSMode != "tls" {
		return in, errors.New("TLS 模式无效")
	}
	if in.Priority < 1 || in.Priority > 9999 || in.MinuteLimit < 0 || in.DailyLimit < 0 || in.MinuteLimit > 100000 || in.DailyLimit > 10000000 {
		return in, errors.New("优先级或发送额度无效")
	}
	in.DomainIDs = cleanIDList(in.DomainIDs)
	in.MailboxIDs = cleanIDList(in.MailboxIDs)
	for _, id := range in.DomainIDs {
		var count int
		if err := a.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM domains WHERE id=?`, id).Scan(&count); err != nil || count == 0 {
			return in, errors.New("中继包含不存在的域名")
		}
	}
	for _, id := range in.MailboxIDs {
		var count int
		if err := a.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM mailboxes WHERE id=?`, id).Scan(&count); err != nil || count == 0 {
			return in, errors.New("中继包含不存在的发件人")
		}
	}
	return in, nil
}

func (a *App) listSMTPRelays(ctx context.Context) ([]SMTPRelay, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT id,name,host,port,username,password_ciphertext,tls_mode,enabled,priority,minute_limit,daily_limit,domain_ids_json,mailbox_ids_json,failure_count,circuit_open_until,last_error,last_success_at,created_at,updated_at FROM smtp_relays ORDER BY priority,created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []SMTPRelay{}
	for rows.Next() {
		item, err := scanSMTPRelay(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range items {
		items[index].MinuteUsed, items[index].DailyUsed = a.smtpRelayUsage(ctx, items[index].ID)
	}
	return items, nil
}

type smtpRelayScanner interface{ Scan(...any) error }

func scanSMTPRelay(row smtpRelayScanner) (SMTPRelay, error) {
	var item SMTPRelay
	var password, domainsJSON, mailboxesJSON, created, updated string
	var enabled int
	var circuit, success sql.NullString
	err := row.Scan(&item.ID, &item.Name, &item.Host, &item.Port, &item.Username, &password, &item.TLSMode, &enabled, &item.Priority, &item.MinuteLimit, &item.DailyLimit, &domainsJSON, &mailboxesJSON, &item.FailureCount, &circuit, &item.LastError, &success, &created, &updated)
	if err != nil {
		return item, err
	}
	item.Enabled, item.PasswordSet = enabled == 1, password != ""
	item.DomainIDs, item.MailboxIDs = jsonDecodeSlice(domainsJSON), jsonDecodeSlice(mailboxesJSON)
	item.CreatedAt, item.UpdatedAt = parseTime(created), parseTime(updated)
	item.CircuitOpenUntil, item.LastSuccessAt = nullableCampaignTime(circuit), nullableCampaignTime(success)
	return item, nil
}

func (a *App) smtpRelayByID(ctx context.Context, id string) (SMTPRelay, error) {
	item, err := scanSMTPRelay(a.db.QueryRowContext(ctx, `SELECT id,name,host,port,username,password_ciphertext,tls_mode,enabled,priority,minute_limit,daily_limit,domain_ids_json,mailbox_ids_json,failure_count,circuit_open_until,last_error,last_success_at,created_at,updated_at FROM smtp_relays WHERE id=?`, id))
	if err == nil {
		item.MinuteUsed, item.DailyUsed = a.smtpRelayUsage(ctx, id)
	}
	return item, err
}

func (a *App) smtpRelayRuntimeByID(ctx context.Context, id string) (smtpRelayRuntime, error) {
	item, err := a.smtpRelayByID(ctx, id)
	if err != nil {
		return smtpRelayRuntime{}, err
	}
	var ciphertext string
	if err := a.db.QueryRowContext(ctx, `SELECT password_ciphertext FROM smtp_relays WHERE id=?`, id).Scan(&ciphertext); err != nil {
		return smtpRelayRuntime{}, err
	}
	password, err := a.decryptSMTPRelayPassword(ciphertext)
	if err != nil {
		return smtpRelayRuntime{}, err
	}
	return smtpRelayRuntime{SMTPRelay: item, Password: password}, nil
}

func (r smtpRelayRuntime) config(base Config) Config {
	base.SMTPHost, base.SMTPPort, base.SMTPUsername, base.SMTPPassword = r.Host, strconv.Itoa(r.Port), r.Username, r.Password
	base.SMTPRequireTLS = r.TLSMode != "plain"
	if r.TLSMode == "tls" {
		base.SMTPPort = strconv.Itoa(r.Port)
	}
	return base
}

func (a *App) smtpRelayUsage(ctx context.Context, relayID string) (int, int) {
	now := a.now().UTC()
	var minute, day int
	_ = a.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM smtp_relay_events WHERE relay_id=? AND event='reserved' AND created_at>=?`, relayID, now.Add(-time.Minute).Format(time.RFC3339Nano)).Scan(&minute)
	_ = a.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM smtp_relay_events WHERE relay_id=? AND event='reserved' AND created_at>=?`, relayID, now.Format("2006-01-02T00:00:00Z")).Scan(&day)
	return minute, day
}

func (a *App) relayCandidates(ctx context.Context, mailboxID string) ([]smtpRelayRuntime, error) {
	var domainID string
	if err := a.db.QueryRowContext(ctx, `SELECT domain_id FROM mailboxes WHERE id=?`, mailboxID).Scan(&domainID); err != nil {
		return nil, err
	}
	items, err := a.listSMTPRelays(ctx)
	if err != nil {
		return nil, err
	}
	result := []smtpRelayRuntime{}
	now := a.now().UTC()
	for _, item := range items {
		if !item.Enabled || item.CircuitOpenUntil != nil && item.CircuitOpenUntil.After(now) {
			continue
		}
		specificity := 0
		if len(item.MailboxIDs) > 0 || len(item.DomainIDs) > 0 {
			if relayListContains(item.MailboxIDs, mailboxID) {
				specificity = 2
			} else if relayListContains(item.DomainIDs, domainID) {
				specificity = 1
			} else {
				continue
			}
		}
		if item.MinuteLimit > 0 && item.MinuteUsed >= item.MinuteLimit || item.DailyLimit > 0 && item.DailyUsed >= item.DailyLimit {
			continue
		}
		runtime, err := a.smtpRelayRuntimeByID(ctx, item.ID)
		if err != nil {
			return nil, fmt.Errorf("无法解密中继 %s 的密码", item.Name)
		}
		runtime.specificity = specificity
		result = append(result, runtime)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].specificity != result[j].specificity {
			return result[i].specificity > result[j].specificity
		}
		return result[i].Priority < result[j].Priority
	})
	return result, nil
}

func relayListContains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func (a *App) reserveSMTPRelay(ctx context.Context, relay smtpRelayRuntime, queueID string) (bool, error) {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	now := a.now().UTC()
	var minute, day int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM smtp_relay_events WHERE relay_id=? AND event='reserved' AND created_at>=?`, relay.ID, now.Add(-time.Minute).Format(time.RFC3339Nano)).Scan(&minute); err != nil {
		return false, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM smtp_relay_events WHERE relay_id=? AND event='reserved' AND created_at>=?`, relay.ID, now.Format("2006-01-02T00:00:00Z")).Scan(&day); err != nil {
		return false, err
	}
	var existing int
	_ = tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM smtp_relay_events WHERE relay_id=? AND queue_id=? AND event='reserved'`, relay.ID, queueID).Scan(&existing)
	if existing == 0 && (relay.MinuteLimit > 0 && minute >= relay.MinuteLimit || relay.DailyLimit > 0 && day >= relay.DailyLimit) {
		return false, nil
	}
	if existing == 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO smtp_relay_events(id,relay_id,queue_id,event,created_at) VALUES(?,?,?,?,?)`, newID("rle"), relay.ID, queueID, "reserved", now.Format(time.RFC3339Nano)); err != nil {
			return false, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE send_queue SET relay_id=? WHERE id=?`, relay.ID, queueID); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (a *App) markSMTPRelaySuccess(ctx context.Context, relayID string) {
	_, _ = a.db.ExecContext(ctx, `UPDATE smtp_relays SET failure_count=0,circuit_open_until=NULL,last_error='',last_success_at=?,updated_at=? WHERE id=?`, a.now().UTC().Format(time.RFC3339Nano), a.now().UTC().Format(time.RFC3339Nano), relayID)
}

func (a *App) markSMTPRelayFailure(ctx context.Context, relayID string, sendErr error) {
	settings, _ := a.deliverabilitySettings(ctx)
	if settings.CircuitFailureThreshold <= 0 {
		settings.CircuitFailureThreshold = 3
	}
	if settings.CircuitMinutes <= 0 {
		settings.CircuitMinutes = 15
	}
	now := a.now().UTC()
	_, _ = a.db.ExecContext(ctx, `UPDATE smtp_relays SET failure_count=failure_count+1,last_error=?,circuit_open_until=CASE WHEN failure_count+1>=? THEN ? ELSE circuit_open_until END,updated_at=? WHERE id=?`, truncateText(sendErr.Error(), 1000), settings.CircuitFailureThreshold, now.Add(time.Duration(settings.CircuitMinutes)*time.Minute).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), relayID)
}

func (a *App) hasUsableSMTPRoute(ctx context.Context) bool {
	if strings.TrimSpace(a.config().SMTPHost) != "" {
		return true
	}
	var count int
	return a.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM smtp_relays WHERE enabled=1`).Scan(&count) == nil && count > 0
}

func (a *App) sendSMTPQueueItem(ctx context.Context, item sendQueueItem) error {
	relays, err := a.relayCandidates(ctx, item.MailboxID)
	if err != nil {
		return smtpPhaseError(err, true)
	}
	var failures []string
	for _, relay := range relays {
		reserved, err := a.reserveSMTPRelay(ctx, relay, item.ID)
		if err != nil {
			return smtpPhaseError(err, true)
		}
		if !reserved {
			continue
		}
		cfg := relay.config(a.config())
		err = sendSMTPWithTLSMode(cfg, relay.TLSMode, item.MailFrom, item.Recipients, item.MIMEBytes)
		if err == nil {
			a.markSMTPRelaySuccess(ctx, relay.ID)
			return nil
		}
		if smtpErrorAffectsRelay(err) {
			a.markSMTPRelayFailure(ctx, relay.ID, err)
		}
		failures = append(failures, relay.Name+": "+err.Error())
		if !smtpErrorFailoverSafe(err) {
			return err
		}
	}
	cfg := a.config()
	if strings.TrimSpace(cfg.SMTPHost) != "" {
		if err := sendSMTPWithConfig(cfg, item.MailFrom, item.Recipients, item.MIMEBytes); err != nil {
			failures = append(failures, "默认通道: "+err.Error())
			return err
		}
		_, _ = a.db.ExecContext(ctx, `UPDATE send_queue SET relay_id='' WHERE id=?`, item.ID)
		return nil
	}
	if len(failures) == 0 {
		if until, reason := a.nextSMTPRelayAvailability(ctx, item.MailboxID); !until.IsZero() {
			return &smtpQueueDelayError{Until: until, Reason: reason}
		}
		return smtpPhaseError(errors.New("没有可用的 SMTP 中继，可能已达到限额或熔断"), true)
	}
	return smtpPhaseError(errors.New(strings.Join(failures, "; ")), true)
}

func (a *App) nextSMTPRelayAvailability(ctx context.Context, mailboxID string) (time.Time, string) {
	var domainID string
	if err := a.db.QueryRowContext(ctx, `SELECT domain_id FROM mailboxes WHERE id=?`, mailboxID).Scan(&domainID); err != nil {
		return time.Time{}, ""
	}
	items, err := a.listSMTPRelays(ctx)
	if err != nil {
		return time.Time{}, ""
	}
	now := a.now().UTC()
	var earliest time.Time
	reason := "SMTP 中继暂不可用，已等待恢复"
	for _, item := range items {
		if !item.Enabled {
			continue
		}
		if len(item.MailboxIDs) > 0 || len(item.DomainIDs) > 0 {
			if !relayListContains(item.MailboxIDs, mailboxID) && !relayListContains(item.DomainIDs, domainID) {
				continue
			}
		}
		available := time.Time{}
		itemReason := ""
		if item.CircuitOpenUntil != nil && item.CircuitOpenUntil.After(now) {
			available, itemReason = *item.CircuitOpenUntil, "SMTP 中继正在熔断，已等待自动恢复"
		}
		if item.MinuteLimit > 0 && item.MinuteUsed >= item.MinuteLimit {
			candidate := now.Add(time.Minute)
			if available.IsZero() || candidate.After(available) {
				available = candidate
			}
			itemReason = "SMTP 中继已达到分钟额度，已等待额度恢复"
		}
		if item.DailyLimit > 0 && item.DailyUsed >= item.DailyLimit {
			candidate := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
			if available.IsZero() || candidate.After(available) {
				available = candidate
			}
			itemReason = "SMTP 中继已达到每日额度，已等待下一个 UTC 自然日"
		}
		if available.After(now) && (earliest.IsZero() || available.Before(earliest)) {
			earliest, reason = available, itemReason
		}
	}
	return earliest, reason
}

func (a *App) deliverabilitySettings(ctx context.Context) (DeliverabilitySettings, error) {
	var item DeliverabilitySettings
	var enabled int
	err := a.db.QueryRowContext(ctx, `SELECT auto_pause,complaint_threshold,bounce_threshold,minimum_sample,circuit_failure_threshold,circuit_minutes FROM deliverability_settings WHERE id='default'`).Scan(&enabled, &item.ComplaintThreshold, &item.BounceThreshold, &item.MinimumSample, &item.CircuitFailureThreshold, &item.CircuitMinutes)
	if err != nil {
		return item, err
	}
	item.AutoPause = enabled == 1
	cfg := a.config()
	item.CallbackConfigured = strings.TrimSpace(cfg.DeliveryWebhookSecret) != ""
	item.RelaySecretConfigured = strings.TrimSpace(cfg.SMTPRelaySecretKey) != ""
	if base, err := url.Parse(strings.TrimRight(strings.TrimSpace(cfg.PublicBaseURL), "/")); err == nil && base.Scheme != "" && base.Host != "" {
		item.CallbackURL = strings.TrimRight(base.String(), "/") + "/api/open/v1/delivery-events"
	}
	return item, nil
}

func (a *App) smtpRelayKey() ([]byte, error) {
	secret := strings.TrimSpace(a.config().SMTPRelaySecretKey)
	if secret == "" {
		return nil, errors.New("请先配置 LANQIN_SMTP_RELAY_SECRET_KEY；一键安装会自动生成")
	}
	sum := sha256.Sum256([]byte(secret))
	return sum[:], nil
}

func (a *App) encryptSMTPRelayPassword(password string) (string, error) {
	key, err := a.smtpRelayKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(append(nonce, gcm.Seal(nil, nonce, []byte(password), nil)...)), nil
}

func (a *App) decryptSMTPRelayPassword(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	key, err := a.smtpRelayKey()
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("invalid encrypted SMTP relay password")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func truncateText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
