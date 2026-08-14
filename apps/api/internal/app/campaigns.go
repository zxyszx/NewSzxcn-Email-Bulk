package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

const (
	campaignStatusDraft     = "draft"
	campaignStatusScheduled = "scheduled"
	campaignStatusRunning   = "running"
	campaignStatusPaused    = "paused"
	campaignStatusCompleted = "completed"
	campaignStatusCanceled  = "canceled"

	campaignRecipientPending    = "pending"
	campaignRecipientQueued     = "queued"
	campaignRecipientDelivered  = "delivered"
	campaignRecipientFailed     = "failed"
	campaignRecipientSuppressed = "suppressed"
	campaignRecipientCanceled   = "canceled"

	maxCampaignRecipients = 50000
	maxCampaignBodyBytes  = 2 << 20
)

type Campaign struct {
	ID               string              `json:"id"`
	MailboxID        string              `json:"mailboxId"`
	MailboxAddress   string              `json:"mailboxAddress"`
	Senders          []CampaignSender    `json:"senders,omitempty"`
	SenderCount      int                 `json:"senderCount"`
	Name             string              `json:"name"`
	Subject          string              `json:"subject"`
	BodyText         string              `json:"text,omitempty"`
	BodyHTML         string              `json:"html,omitempty"`
	Status           string              `json:"status"`
	RatePerMinute    int                 `json:"ratePerMinute"`
	ConsentConfirmed bool                `json:"consentConfirmed"`
	TotalCount       int                 `json:"totalCount"`
	PendingCount     int                 `json:"pendingCount"`
	QueuedCount      int                 `json:"queuedCount"`
	DeliveredCount   int                 `json:"deliveredCount"`
	FailedCount      int                 `json:"failedCount"`
	SuppressedCount  int                 `json:"suppressedCount"`
	ScheduledAt      *time.Time          `json:"scheduledAt,omitempty"`
	StartedAt        *time.Time          `json:"startedAt,omitempty"`
	CompletedAt      *time.Time          `json:"completedAt,omitempty"`
	CreatedAt        time.Time           `json:"createdAt"`
	UpdatedAt        time.Time           `json:"updatedAt"`
	Recipients       []CampaignRecipient `json:"recipients,omitempty"`
}

type CampaignSender struct {
	MailboxID string `json:"mailboxId"`
	Address   string `json:"address"`
	Count     int    `json:"recipientCount"`
}

type CampaignRecipient struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Name        string     `json:"name,omitempty"`
	MailboxID   string     `json:"mailboxId,omitempty"`
	Status      string     `json:"status"`
	LastError   string     `json:"lastError,omitempty"`
	QueuedAt    *time.Time `json:"queuedAt,omitempty"`
	DeliveredAt *time.Time `json:"deliveredAt,omitempty"`
}

type CampaignSuppression struct {
	ID         string    `json:"id"`
	Email      string    `json:"email"`
	Reason     string    `json:"reason"`
	Source     string    `json:"source"`
	CampaignID string    `json:"campaignId,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type campaignInput struct {
	MailboxID        string   `json:"mailboxId"`
	MailboxIDs       []string `json:"mailboxIds"`
	Name             string   `json:"name"`
	Subject          string   `json:"subject"`
	Text             string   `json:"text"`
	HTML             string   `json:"html"`
	RatePerMinute    int      `json:"ratePerMinute"`
	ScheduledAt      string   `json:"scheduledAt"`
	ConsentConfirmed bool     `json:"consentConfirmed"`
	Recipients       []struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"recipients"`
}

type normalizedCampaignInput struct {
	MailboxID        string
	MailboxIDs       []string
	Name             string
	Subject          string
	Text             string
	HTML             string
	RatePerMinute    int
	ScheduledAt      *time.Time
	ConsentConfirmed bool
	Recipients       []CampaignRecipient
}

func (a *App) handleCreateCampaign(w http.ResponseWriter, r *http.Request) {
	var req campaignInput
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, err)
		return
	}
	in, err := a.normalizeCampaignInput(r.Context(), req)
	if err != nil {
		badRequest(w, err)
		return
	}
	now := a.now().UTC()
	campaignID := newID("cmp")
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create campaign")
		return
	}
	defer tx.Rollback()
	var scheduled any
	if in.ScheduledAt != nil {
		scheduled = in.ScheduledAt.Format(time.RFC3339Nano)
	}
	_, err = tx.ExecContext(r.Context(), `INSERT INTO campaigns(id,user_id,mailbox_id,name,subject,body_text,body_html,status,rate_per_minute,consent_confirmed,total_count,pending_count,scheduled_at,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, campaignID, currentUser(r).ID, in.MailboxID, in.Name, in.Subject, in.Text, in.HTML, campaignStatusDraft, in.RatePerMinute, boolInt(in.ConsentConfirmed), len(in.Recipients), len(in.Recipients), scheduled, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create campaign")
		return
	}
	if err := insertCampaignRecipients(r.Context(), tx, campaignID, in.Recipients, now); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to add campaign recipients")
		return
	}
	if err := insertCampaignSenders(r.Context(), tx, campaignID, in.MailboxIDs, now); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to add campaign senders")
		return
	}
	if err := tx.Commit(); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to save campaign")
		return
	}
	campaign, _ := a.loadCampaign(r.Context(), campaignID, false)
	respondJSON(w, http.StatusCreated, campaign)
}

func (a *App) handleUpdateCampaign(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var status string
	if err := a.db.QueryRowContext(r.Context(), `SELECT status FROM campaigns WHERE id=?`, id).Scan(&status); err != nil {
		respondError(w, http.StatusNotFound, "campaign not found")
		return
	}
	if status != campaignStatusDraft {
		badRequest(w, errors.New("only draft campaigns can be edited"))
		return
	}
	var req campaignInput
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, err)
		return
	}
	in, err := a.normalizeCampaignInput(r.Context(), req)
	if err != nil {
		badRequest(w, err)
		return
	}
	now := a.now().UTC()
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update campaign")
		return
	}
	defer tx.Rollback()
	var scheduled any
	if in.ScheduledAt != nil {
		scheduled = in.ScheduledAt.Format(time.RFC3339Nano)
	}
	res, err := tx.ExecContext(r.Context(), `UPDATE campaigns SET mailbox_id=?,name=?,subject=?,body_text=?,body_html=?,rate_per_minute=?,consent_confirmed=?,total_count=?,pending_count=?,queued_count=0,delivered_count=0,failed_count=0,suppressed_count=0,scheduled_at=?,updated_at=? WHERE id=? AND status='draft'`,
		in.MailboxID, in.Name, in.Subject, in.Text, in.HTML, in.RatePerMinute, boolInt(in.ConsentConfirmed), len(in.Recipients), len(in.Recipients), scheduled, now.Format(time.RFC3339Nano), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update campaign")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		respondError(w, http.StatusNotFound, "campaign not found")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM campaign_recipients WHERE campaign_id=?`, id); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update recipients")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM campaign_senders WHERE campaign_id=?`, id); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update senders")
		return
	}
	if err := insertCampaignRecipients(r.Context(), tx, id, in.Recipients, now); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update recipients")
		return
	}
	if err := insertCampaignSenders(r.Context(), tx, id, in.MailboxIDs, now); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update senders")
		return
	}
	if err := tx.Commit(); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to save campaign")
		return
	}
	campaign, _ := a.loadCampaign(r.Context(), id, false)
	respondJSON(w, http.StatusOK, campaign)
}

func (a *App) normalizeCampaignInput(ctx context.Context, req campaignInput) (normalizedCampaignInput, error) {
	var out normalizedCampaignInput
	seenMailboxes := map[string]bool{}
	mailboxIDs := append([]string{}, req.MailboxIDs...)
	if len(mailboxIDs) == 0 && strings.TrimSpace(req.MailboxID) != "" {
		mailboxIDs = append(mailboxIDs, req.MailboxID)
	}
	for _, id := range mailboxIDs {
		id = strings.TrimSpace(id)
		if id == "" || seenMailboxes[id] {
			continue
		}
		mb, err := a.mailboxByID(ctx, id)
		if err != nil || mb.Status != "active" {
			return out, errors.New("所选发件邮箱中包含不可用账号")
		}
		seenMailboxes[id] = true
		out.MailboxIDs = append(out.MailboxIDs, id)
	}
	if len(out.MailboxIDs) == 0 {
		return out, errors.New("请至少选择一个正常使用的发件邮箱")
	}
	out.MailboxID = out.MailboxIDs[0]
	out.Name = strings.TrimSpace(req.Name)
	if out.Name == "" || len([]rune(out.Name)) > 120 || hasHeaderBreak(out.Name) {
		return out, errors.New("活动名称不能为空且不能超过 120 个字符")
	}
	out.Subject = strings.TrimSpace(req.Subject)
	if out.Subject == "" || len([]rune(out.Subject)) > 255 || hasHeaderBreak(out.Subject) {
		return out, errors.New("邮件主题不能为空且不能超过 255 个字符")
	}
	if len(req.Text)+len(req.HTML) > maxCampaignBodyBytes {
		return out, errors.New("邮件正文不能超过 2 MB")
	}
	out.HTML = a.policy.Sanitize(req.HTML)
	out.Text = strings.TrimSpace(req.Text)
	if out.Text == "" {
		out.Text = stripTags(out.HTML)
	}
	if strings.TrimSpace(out.HTML) == "" {
		out.HTML = "<p>" + htmlEscape(out.Text) + "</p>"
	}
	if strings.TrimSpace(out.Text) == "" {
		return out, errors.New("邮件正文不能为空")
	}
	out.RatePerMinute = req.RatePerMinute
	if out.RatePerMinute == 0 {
		out.RatePerMinute = 30
	}
	if out.RatePerMinute < 1 || out.RatePerMinute > 300 {
		return out, errors.New("发送速度必须在每分钟 1 至 300 封之间")
	}
	out.ConsentConfirmed = req.ConsentConfirmed
	if value := strings.TrimSpace(req.ScheduledAt); value != "" {
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return out, errors.New("定时发送时间格式无效")
		}
		parsed = parsed.UTC()
		out.ScheduledAt = &parsed
	}
	suppressedEmails := map[string]struct{}{}
	suppressionRows, err := a.db.QueryContext(ctx, `SELECT email FROM campaign_suppressions`)
	if err != nil {
		return out, errors.New("读取退订名单失败")
	}
	for suppressionRows.Next() {
		var emailAddress string
		if err := suppressionRows.Scan(&emailAddress); err != nil {
			suppressionRows.Close()
			return out, errors.New("读取退订名单失败")
		}
		suppressedEmails[normalizeEmail(emailAddress)] = struct{}{}
	}
	if err := suppressionRows.Err(); err != nil {
		suppressionRows.Close()
		return out, errors.New("读取退订名单失败")
	}
	if err := suppressionRows.Close(); err != nil {
		return out, errors.New("读取退订名单失败")
	}
	seen := map[string]bool{}
	for _, item := range req.Recipients {
		address, err := mail.ParseAddress(strings.TrimSpace(item.Email))
		if err != nil {
			return out, fmt.Errorf("收件人地址无效：%s", item.Email)
		}
		emailAddress := normalizeEmail(address.Address)
		if _, err := mail.ParseAddress(emailAddress); err != nil || !strings.Contains(emailAddress, "@") {
			return out, fmt.Errorf("收件人地址无效：%s", item.Email)
		}
		if seen[emailAddress] {
			continue
		}
		seen[emailAddress] = true
		name := strings.TrimSpace(item.Name)
		if name == "" {
			name = strings.TrimSpace(address.Name)
		}
		if len([]rune(name)) > 120 || hasHeaderBreak(name) {
			return out, fmt.Errorf("收件人名称无效：%s", emailAddress)
		}
		status := campaignRecipientPending
		if _, suppressed := suppressedEmails[emailAddress]; suppressed {
			status = campaignRecipientSuppressed
		}
		mailboxID := out.MailboxIDs[len(out.Recipients)%len(out.MailboxIDs)]
		out.Recipients = append(out.Recipients, CampaignRecipient{ID: newID("crp"), Email: emailAddress, Name: name, MailboxID: mailboxID, Status: status})
		if len(out.Recipients) > maxCampaignRecipients {
			return out, fmt.Errorf("单个活动最多支持 %d 个收件人", maxCampaignRecipients)
		}
	}
	if len(out.Recipients) == 0 {
		return out, errors.New("请至少添加一个有效收件人")
	}
	return out, nil
}

func insertCampaignRecipients(ctx context.Context, tx *sql.Tx, campaignID string, recipients []CampaignRecipient, now time.Time) error {
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO campaign_recipients(id,campaign_id,mailbox_id,email,name,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, item := range recipients {
		if _, err := stmt.ExecContext(ctx, item.ID, campaignID, item.MailboxID, item.Email, item.Name, item.Status, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE campaigns SET pending_count=(SELECT COUNT(1) FROM campaign_recipients WHERE campaign_id=? AND status='pending'),suppressed_count=(SELECT COUNT(1) FROM campaign_recipients WHERE campaign_id=? AND status='suppressed') WHERE id=?`, campaignID, campaignID, campaignID)
	return err
}

func insertCampaignSenders(ctx context.Context, tx *sql.Tx, campaignID string, mailboxIDs []string, now time.Time) error {
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO campaign_senders(campaign_id,mailbox_id,sort_order,created_at) VALUES(?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for index, mailboxID := range mailboxIDs {
		if _, err := stmt.ExecContext(ctx, campaignID, mailboxID, index, now.Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) handleListCampaigns(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.QueryContext(r.Context(), campaignSelect+` ORDER BY c.created_at DESC LIMIT 200`)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load campaigns")
		return
	}
	defer rows.Close()
	items := []Campaign{}
	for rows.Next() {
		item, err := scanCampaign(rows)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to load campaigns")
			return
		}
		items = append(items, item)
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *App) handleGetCampaign(w http.ResponseWriter, r *http.Request) {
	item, err := a.loadCampaign(r.Context(), chi.URLParam(r, "id"), true)
	if err != nil {
		respondError(w, http.StatusNotFound, "campaign not found")
		return
	}
	respondJSON(w, http.StatusOK, item)
}

const campaignSelect = `SELECT c.id,c.mailbox_id,mb.address,(SELECT COUNT(1) FROM campaign_senders cs WHERE cs.campaign_id=c.id),c.name,c.subject,c.body_text,c.body_html,c.status,c.rate_per_minute,c.consent_confirmed,c.total_count,c.pending_count,c.queued_count,c.delivered_count,c.failed_count,c.suppressed_count,c.scheduled_at,c.started_at,c.completed_at,c.created_at,c.updated_at FROM campaigns c JOIN mailboxes mb ON mb.id=c.mailbox_id`

type campaignScanner interface{ Scan(dest ...any) error }

func scanCampaign(row campaignScanner) (Campaign, error) {
	var item Campaign
	var consent int
	var scheduled, started, completed sql.NullString
	var created, updated string
	err := row.Scan(&item.ID, &item.MailboxID, &item.MailboxAddress, &item.SenderCount, &item.Name, &item.Subject, &item.BodyText, &item.BodyHTML, &item.Status, &item.RatePerMinute, &consent, &item.TotalCount, &item.PendingCount, &item.QueuedCount, &item.DeliveredCount, &item.FailedCount, &item.SuppressedCount, &scheduled, &started, &completed, &created, &updated)
	if err != nil {
		return item, err
	}
	item.ConsentConfirmed = consent == 1
	item.CreatedAt, item.UpdatedAt = parseTime(created), parseTime(updated)
	item.ScheduledAt, item.StartedAt, item.CompletedAt = nullableCampaignTime(scheduled), nullableCampaignTime(started), nullableCampaignTime(completed)
	return item, nil
}

func nullableCampaignTime(value sql.NullString) *time.Time {
	if !value.Valid || value.String == "" {
		return nil
	}
	t := parseTime(value.String)
	return &t
}

func (a *App) loadCampaign(ctx context.Context, id string, withRecipients bool) (Campaign, error) {
	item, err := scanCampaign(a.db.QueryRowContext(ctx, campaignSelect+` WHERE c.id=?`, id))
	if err != nil {
		return item, err
	}
	if !withRecipients {
		return item, nil
	}
	senderRows, err := a.db.QueryContext(ctx, `SELECT cs.mailbox_id,mb.address,COUNT(cr.id) FROM campaign_senders cs JOIN mailboxes mb ON mb.id=cs.mailbox_id LEFT JOIN campaign_recipients cr ON cr.campaign_id=cs.campaign_id AND cr.mailbox_id=cs.mailbox_id WHERE cs.campaign_id=? GROUP BY cs.mailbox_id,mb.address,cs.sort_order ORDER BY cs.sort_order`, id)
	if err != nil {
		return item, err
	}
	for senderRows.Next() {
		var sender CampaignSender
		if err := senderRows.Scan(&sender.MailboxID, &sender.Address, &sender.Count); err != nil {
			senderRows.Close()
			return item, err
		}
		item.Senders = append(item.Senders, sender)
	}
	if err := senderRows.Close(); err != nil {
		return item, err
	}
	rows, err := a.db.QueryContext(ctx, `SELECT id,mailbox_id,email,name,status,last_error,queued_at,delivered_at FROM campaign_recipients WHERE campaign_id=? ORDER BY created_at LIMIT 500`, id)
	if err != nil {
		return item, err
	}
	defer rows.Close()
	item.Recipients = []CampaignRecipient{}
	for rows.Next() {
		var recipient CampaignRecipient
		var queued, delivered sql.NullString
		if err := rows.Scan(&recipient.ID, &recipient.MailboxID, &recipient.Email, &recipient.Name, &recipient.Status, &recipient.LastError, &queued, &delivered); err != nil {
			return item, err
		}
		recipient.QueuedAt, recipient.DeliveredAt = nullableCampaignTime(queued), nullableCampaignTime(delivered)
		item.Recipients = append(item.Recipients, recipient)
	}
	return item, rows.Err()
}

func (a *App) handleStartCampaign(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	item, err := a.loadCampaign(r.Context(), id, false)
	if err != nil {
		respondError(w, http.StatusNotFound, "campaign not found")
		return
	}
	if item.Status != campaignStatusDraft {
		badRequest(w, errors.New("只有草稿活动可以启动"))
		return
	}
	if !item.ConsentConfirmed {
		badRequest(w, errors.New("启动前必须确认所有收件人已同意接收邮件"))
		return
	}
	if strings.TrimSpace(a.config().SMTPHost) == "" {
		badRequest(w, errors.New("请先在系统设置中配置发信 SMTP"))
		return
	}
	baseURL := strings.TrimRight(strings.TrimSpace(a.config().PublicBaseURL), "/")
	if parsed, err := url.Parse(baseURL); err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		badRequest(w, errors.New("请先在系统设置中填写正确的外部访问地址，以便退订链接正常工作"))
		return
	}
	if item.PendingCount == 0 {
		badRequest(w, errors.New("没有可发送的收件人，名单可能已全部退订"))
		return
	}
	now := a.now().UTC()
	status := campaignStatusRunning
	next := now
	if item.ScheduledAt != nil && item.ScheduledAt.After(now) {
		status = campaignStatusScheduled
		next = *item.ScheduledAt
	}
	_, err = a.db.ExecContext(r.Context(), `UPDATE campaigns SET status=?,next_dispatch_at=?,started_at=CASE WHEN ?='running' THEN COALESCE(started_at,?) ELSE started_at END,updated_at=? WHERE id=? AND status='draft'`, status, next.Format(time.RFC3339Nano), status, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to start campaign")
		return
	}
	item, _ = a.loadCampaign(r.Context(), id, false)
	respondJSON(w, http.StatusOK, item)
}

func (a *App) handlePauseCampaign(w http.ResponseWriter, r *http.Request) {
	a.changeCampaignStatus(w, r, []string{campaignStatusRunning, campaignStatusScheduled}, campaignStatusPaused)
}

func (a *App) handleResumeCampaign(w http.ResponseWriter, r *http.Request) {
	a.changeCampaignStatus(w, r, []string{campaignStatusPaused}, campaignStatusRunning)
}

func (a *App) changeCampaignStatus(w http.ResponseWriter, r *http.Request, from []string, to string) {
	id := chi.URLParam(r, "id")
	now := a.now().UTC().Format(time.RFC3339Nano)
	query := `UPDATE campaigns SET status=?,updated_at=?`
	args := []any{to, now}
	if to == campaignStatusRunning {
		query += `,next_dispatch_at=?,started_at=COALESCE(started_at,?)`
		args = append(args, now, now)
	}
	query += ` WHERE id=? AND status IN (` + strings.TrimSuffix(strings.Repeat("?,", len(from)), ",") + `)`
	args = append(args, id)
	for _, status := range from {
		args = append(args, status)
	}
	res, err := a.db.ExecContext(r.Context(), query, args...)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update campaign")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		badRequest(w, errors.New("当前活动状态不支持此操作"))
		return
	}
	item, _ := a.loadCampaign(r.Context(), id, false)
	respondJSON(w, http.StatusOK, item)
}

func (a *App) handleCancelCampaign(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	now := a.now().UTC().Format(time.RFC3339Nano)
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to cancel campaign")
		return
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(r.Context(), `UPDATE campaigns SET status='canceled',completed_at=?,updated_at=? WHERE id=? AND status IN ('draft','scheduled','running','paused')`, now, now, id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to cancel campaign")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		badRequest(w, errors.New("当前活动状态不支持取消"))
		return
	}
	_, _ = tx.ExecContext(r.Context(), `UPDATE campaign_recipients SET status='canceled',updated_at=? WHERE campaign_id=? AND status='pending'`, now, id)
	_, _ = tx.ExecContext(r.Context(), `UPDATE send_queue SET status='canceled',updated_at=? WHERE id IN (SELECT queue_id FROM campaign_recipients WHERE campaign_id=?) AND status IN ('queued','failed')`, now, id)
	if err := tx.Commit(); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to cancel campaign")
		return
	}
	_ = a.refreshCampaignCounts(r.Context(), id)
	item, _ := a.loadCampaign(r.Context(), id, false)
	respondJSON(w, http.StatusOK, item)
}

func (a *App) handleRetryCampaignRecipients(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		RecipientIDs []string `json:"recipientIds"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, err)
		return
	}
	now := a.now().UTC().Format(time.RFC3339Nano)
	query := `UPDATE campaign_recipients SET status='pending',last_error='',updated_at=? WHERE campaign_id=? AND status='failed'`
	args := []any{now, id}
	if len(req.RecipientIDs) > 0 {
		if len(req.RecipientIDs) > 5000 {
			badRequest(w, errors.New("单次最多重试 5000 个收件人"))
			return
		}
		query += ` AND id IN (` + strings.TrimSuffix(strings.Repeat("?,", len(req.RecipientIDs)), ",") + `)`
		for _, recipientID := range req.RecipientIDs {
			args = append(args, strings.TrimSpace(recipientID))
		}
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to retry recipients")
		return
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(r.Context(), query, args...)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to retry recipients")
		return
	}
	retried, _ := res.RowsAffected()
	if retried == 0 {
		badRequest(w, errors.New("没有可重试的失败收件人"))
		return
	}
	_, err = tx.ExecContext(r.Context(), `UPDATE campaigns SET status='running',completed_at=NULL,next_dispatch_at=?,updated_at=? WHERE id=? AND status IN ('running','paused','completed')`, now, now, id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to restart campaign")
		return
	}
	if err := tx.Commit(); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to retry recipients")
		return
	}
	_ = a.refreshCampaignCounts(r.Context(), id)
	item, _ := a.loadCampaign(r.Context(), id, false)
	respondJSON(w, http.StatusOK, map[string]any{"retried": retried, "campaign": item})
}

func (a *App) campaignWorker(ctx context.Context) {
	a.log.Info("campaign worker started")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := a.processCampaigns(ctx); err != nil && !errors.Is(err, context.Canceled) {
			a.log.Warn("campaign worker failed", "error", err)
		}
		select {
		case <-ctx.Done():
			a.log.Info("campaign worker stopped")
			return
		case <-ticker.C:
		}
	}
}

func (a *App) processCampaigns(ctx context.Context) error {
	if err := a.syncCampaignQueueStatuses(ctx); err != nil {
		return err
	}
	now := a.now().UTC()
	_, err := a.db.ExecContext(ctx, `UPDATE campaigns SET status='running',started_at=COALESCE(started_at,?),next_dispatch_at=COALESCE(next_dispatch_at,?),updated_at=? WHERE status='scheduled' AND scheduled_at<=?`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	rows, err := a.db.QueryContext(ctx, `SELECT id,rate_per_minute,next_dispatch_at FROM campaigns WHERE status='running' ORDER BY created_at`)
	if err != nil {
		return err
	}
	type dueCampaign struct {
		id   string
		rate int
		next sql.NullString
	}
	var due []dueCampaign
	for rows.Next() {
		var item dueCampaign
		if err := rows.Scan(&item.id, &item.rate, &item.next); err != nil {
			rows.Close()
			return err
		}
		due = append(due, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range due {
		if err := a.dispatchCampaign(ctx, item.id, item.rate, item.next, now); err != nil {
			a.log.Warn("campaign dispatch failed", "campaign_id", item.id, "error", err)
		}
		if err := a.refreshCampaignCounts(ctx, item.id); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) dispatchCampaign(ctx context.Context, campaignID string, rate int, nextValue sql.NullString, now time.Time) error {
	if rate < 1 {
		rate = 1
	}
	next := now
	if nextValue.Valid && nextValue.String != "" {
		next = parseTime(nextValue.String)
	}
	if next.After(now) {
		return nil
	}
	interval := time.Minute / time.Duration(rate)
	count := int(now.Sub(next)/interval) + 1
	if count > 20 {
		count = 20
	}
	rows, err := a.db.QueryContext(ctx, `SELECT id,mailbox_id,email,name FROM campaign_recipients WHERE campaign_id=? AND status='pending' ORDER BY created_at LIMIT ?`, campaignID, count)
	if err != nil {
		return err
	}
	var recipients []CampaignRecipient
	for rows.Next() {
		var recipient CampaignRecipient
		if err := rows.Scan(&recipient.ID, &recipient.MailboxID, &recipient.Email, &recipient.Name); err != nil {
			rows.Close()
			return err
		}
		recipients = append(recipients, recipient)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, recipient := range recipients {
		queueID, err := a.enqueueCampaignRecipient(ctx, campaignID, recipient, now)
		if err != nil {
			_, _ = a.db.ExecContext(ctx, `UPDATE campaign_recipients SET status='failed',last_error=?,updated_at=? WHERE id=? AND status='pending'`, truncateCampaignError(err.Error()), now.Format(time.RFC3339Nano), recipient.ID)
		} else {
			_, _ = a.db.ExecContext(ctx, `UPDATE campaign_recipients SET status='queued',queue_id=?,queued_at=?,updated_at=? WHERE id=? AND status='pending'`, queueID, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), recipient.ID)
		}
		next = next.Add(interval)
	}
	if len(recipients) == 0 {
		next = now.Add(interval)
	}
	_, err = a.db.ExecContext(ctx, `UPDATE campaigns SET next_dispatch_at=?,updated_at=? WHERE id=? AND status='running'`, next.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), campaignID)
	return err
}

func (a *App) enqueueCampaignRecipient(ctx context.Context, campaignID string, recipient CampaignRecipient, now time.Time) (string, error) {
	var userID, mailboxID, mailboxAddress, fromName, subject, bodyText, bodyHTML string
	err := a.db.QueryRowContext(ctx, `SELECT c.user_id,cr.mailbox_id,mb.address,mb.display_name,c.subject,c.body_text,c.body_html FROM campaigns c JOIN campaign_recipients cr ON cr.campaign_id=c.id JOIN mailboxes mb ON mb.id=cr.mailbox_id WHERE c.id=? AND cr.id=? AND c.status='running' AND mb.status='active'`, campaignID, recipient.ID).Scan(&userID, &mailboxID, &mailboxAddress, &fromName, &subject, &bodyText, &bodyHTML)
	if err != nil {
		return "", err
	}
	token, err := a.campaignUnsubscribeToken(ctx, recipient.ID)
	if err != nil {
		return "", err
	}
	unsubscribeURL := strings.TrimRight(strings.TrimSpace(a.config().PublicBaseURL), "/") + "/api/unsubscribe?token=" + url.QueryEscape(token)
	personalText := bodyText + "\n\n--\n不再接收此类邮件：" + unsubscribeURL
	personalHTML := bodyHTML + `<div style="margin-top:28px;padding-top:16px;border-top:1px solid #e5e7eb;color:#64748b;font-size:12px;line-height:1.6;text-align:center">您收到此邮件是因为曾同意接收相关消息。<a href="` + html.EscapeString(unsubscribeURL) + `" style="color:#475569">点击退订</a></div>`
	messageID := fmt.Sprintf("<campaign-%s@%s>", recipient.ID, strings.SplitN(mailboxAddress, "@", 2)[1])
	mimeBytes, err := BuildMIME(MIMEMessage{
		From: mailboxAddress, FromName: fromName, To: []string{recipient.Email}, Subject: subject, Text: personalText, HTML: personalHTML, MessageID: messageID, Date: now,
		Headers: map[string]string{
			"List-Unsubscribe":      "<" + unsubscribeURL + ">",
			"List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
			"Precedence":            "bulk",
			"X-Campaign-ID":         campaignID,
		},
	})
	if err != nil {
		return "", err
	}
	return a.enqueueSend(ctx, sendQueueInput{UserID: userID, MailboxID: mailboxID, MessageID: messageID, Source: sendSourceCampaign, MailFrom: mailboxAddress, HeaderFrom: mailboxAddress, Recipients: []string{recipient.Email}, MIMEBytes: mimeBytes, Now: now})
}

func (a *App) syncCampaignQueueStatuses(ctx context.Context) error {
	now := a.now().UTC().Format(time.RFC3339Nano)
	statements := []string{
		`UPDATE campaign_recipients SET status='delivered',delivered_at=(SELECT delivered_at FROM send_queue WHERE id=queue_id),last_error='',updated_at=? WHERE status='queued' AND queue_id IN (SELECT id FROM send_queue WHERE status='delivered')`,
		`UPDATE campaign_recipients SET status='failed',last_error=COALESCE((SELECT last_error FROM send_queue WHERE id=queue_id),''),updated_at=? WHERE status='queued' AND queue_id IN (SELECT id FROM send_queue WHERE status='failed' AND attempt_count>=max_attempts)`,
		`UPDATE campaign_recipients SET status='canceled',updated_at=? WHERE status='queued' AND queue_id IN (SELECT id FROM send_queue WHERE status='canceled')`,
	}
	for _, statement := range statements {
		if _, err := a.db.ExecContext(ctx, statement, now); err != nil {
			return err
		}
	}
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM campaigns WHERE status IN ('running','paused','scheduled')`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		if err := a.refreshCampaignCounts(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) refreshCampaignCounts(ctx context.Context, campaignID string) error {
	now := a.now().UTC().Format(time.RFC3339Nano)
	_, err := a.db.ExecContext(ctx, `UPDATE campaigns SET
		total_count=(SELECT COUNT(1) FROM campaign_recipients WHERE campaign_id=?),
		pending_count=(SELECT COUNT(1) FROM campaign_recipients WHERE campaign_id=? AND status='pending'),
		queued_count=(SELECT COUNT(1) FROM campaign_recipients WHERE campaign_id=? AND status='queued'),
		delivered_count=(SELECT COUNT(1) FROM campaign_recipients WHERE campaign_id=? AND status='delivered'),
		failed_count=(SELECT COUNT(1) FROM campaign_recipients WHERE campaign_id=? AND status='failed'),
		suppressed_count=(SELECT COUNT(1) FROM campaign_recipients WHERE campaign_id=? AND status='suppressed'),
		updated_at=? WHERE id=?`, campaignID, campaignID, campaignID, campaignID, campaignID, campaignID, now, campaignID)
	if err != nil {
		return err
	}
	_, err = a.db.ExecContext(ctx, `UPDATE campaigns SET status='completed',completed_at=?,updated_at=? WHERE id=? AND status='running' AND pending_count=0 AND queued_count=0`, now, now, campaignID)
	return err
}

func (a *App) campaignUnsubscribeSecret(ctx context.Context) (string, error) {
	now := a.now().UTC().Format(time.RFC3339Nano)
	_, err := a.db.ExecContext(ctx, `INSERT OR IGNORE INTO system_settings(key,value,updated_at) VALUES('campaign.unsubscribe_secret',?,?)`, randomToken(), now)
	if err != nil {
		return "", err
	}
	var secret string
	err = a.db.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key='campaign.unsubscribe_secret'`).Scan(&secret)
	return secret, err
}

func (a *App) campaignUnsubscribeToken(ctx context.Context, recipientID string) (string, error) {
	secret, err := a.campaignUnsubscribeSecret(ctx)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(recipientID))
	return recipientID + "." + fmt.Sprintf("%x", mac.Sum(nil)), nil
}

func (a *App) validateCampaignUnsubscribeToken(ctx context.Context, token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "crp_") {
		return "", errors.New("invalid token")
	}
	expected, err := a.campaignUnsubscribeToken(ctx, parts[0])
	if err != nil {
		return "", err
	}
	if !hmac.Equal([]byte(expected), []byte(token)) {
		return "", errors.New("invalid token")
	}
	return parts[0], nil
}

func (a *App) handleCampaignUnsubscribe(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	token := strings.TrimSpace(r.FormValue("token"))
	recipientID, err := a.validateCampaignUnsubscribeToken(r.Context(), token)
	if err != nil {
		a.renderCampaignUnsubscribePage(w, http.StatusBadRequest, false, "退订链接无效或已损坏")
		return
	}
	var emailAddress, campaignID string
	if err := a.db.QueryRowContext(r.Context(), `SELECT email,campaign_id FROM campaign_recipients WHERE id=?`, recipientID).Scan(&emailAddress, &campaignID); err != nil {
		a.renderCampaignUnsubscribePage(w, http.StatusBadRequest, false, "退订链接无效或已损坏")
		return
	}
	now := a.now().UTC().Format(time.RFC3339Nano)
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO campaign_suppressions(id,email,reason,source,campaign_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(email) DO UPDATE SET reason=excluded.reason,source=excluded.source,campaign_id=excluded.campaign_id,updated_at=excluded.updated_at`, newID("sup"), emailAddress, "收件人主动退订", "unsubscribe", campaignID, now, now)
	if err != nil {
		a.renderCampaignUnsubscribePage(w, http.StatusInternalServerError, false, "暂时无法完成退订，请稍后重试")
		return
	}
	_, _ = a.db.ExecContext(r.Context(), `UPDATE campaign_recipients SET status='suppressed',updated_at=? WHERE email=? AND status='pending'`, now, emailAddress)
	_ = a.refreshCampaignCounts(r.Context(), campaignID)
	a.renderCampaignUnsubscribePage(w, http.StatusOK, true, "您已成功退订，之后的群发活动将不再向此地址发送邮件")
}

func (a *App) renderCampaignUnsubscribePage(w http.ResponseWriter, status int, ok bool, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	title, color, symbol := "退订未完成", "#dc2626", "!"
	if ok {
		title, color, symbol = "退订成功", "#059669", "✓"
	}
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title></head><body style="margin:0;background:#f8fafc;color:#0f172a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif"><main style="min-height:100vh;display:grid;place-items:center;padding:24px"><section style="width:min(100%%,520px);background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:34px 30px"><div style="display:grid;place-items:center;width:44px;height:44px;margin-bottom:20px;border-radius:50%%;background:%s;color:#fff;font-size:24px;font-weight:700">%s</div><h1 style="margin:0 0 14px;font-size:26px">%s</h1><p style="margin:0;color:#475569;line-height:1.7">%s</p><p style="margin:24px 0 0;padding-top:18px;border-top:1px solid #e2e8f0;color:#64748b;font-size:14px">现在可以关闭此页面。</p></section></main></body></html>`, html.EscapeString(title), color, symbol, html.EscapeString(title), html.EscapeString(message))
}

func (a *App) handleListCampaignSuppressions(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.QueryContext(r.Context(), `SELECT id,email,reason,source,campaign_id,created_at,updated_at FROM campaign_suppressions ORDER BY created_at DESC LIMIT 1000`)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to load suppression list")
		return
	}
	defer rows.Close()
	items := []CampaignSuppression{}
	for rows.Next() {
		var item CampaignSuppression
		var created, updated string
		if err := rows.Scan(&item.ID, &item.Email, &item.Reason, &item.Source, &item.CampaignID, &created, &updated); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to load suppression list")
			return
		}
		item.CreatedAt, item.UpdatedAt = parseTime(created), parseTime(updated)
		items = append(items, item)
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *App) handleCreateCampaignSuppression(w http.ResponseWriter, r *http.Request) {
	var req struct{ Email, Reason string }
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, err)
		return
	}
	address, err := mail.ParseAddress(strings.TrimSpace(req.Email))
	if err != nil {
		badRequest(w, errors.New("邮箱地址无效"))
		return
	}
	emailAddress := normalizeEmail(address.Address)
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "管理员手动添加"
	}
	if len([]rune(reason)) > 300 {
		badRequest(w, errors.New("原因不能超过 300 个字符"))
		return
	}
	now := a.now().UTC().Format(time.RFC3339Nano)
	id := newID("sup")
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO campaign_suppressions(id,email,reason,source,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(email) DO UPDATE SET reason=excluded.reason,source=excluded.source,updated_at=excluded.updated_at`, id, emailAddress, reason, "manual", now, now)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to add suppression")
		return
	}
	_, _ = a.db.ExecContext(r.Context(), `UPDATE campaign_recipients SET status='suppressed',updated_at=? WHERE email=? AND status='pending'`, now, emailAddress)
	respondJSON(w, http.StatusCreated, CampaignSuppression{ID: id, Email: emailAddress, Reason: reason, Source: "manual", CreatedAt: parseTime(now), UpdatedAt: parseTime(now)})
}

func (a *App) handleDeleteCampaignSuppression(w http.ResponseWriter, r *http.Request) {
	res, err := a.db.ExecContext(r.Context(), `DELETE FROM campaign_suppressions WHERE id=?`, chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete suppression")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		respondError(w, http.StatusNotFound, "suppression not found")
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func hasHeaderBreak(value string) bool { return strings.ContainsAny(value, "\r\n") }

func truncateCampaignError(value string) string {
	if len(value) <= 1000 {
		return value
	}
	return value[:1000]
}
