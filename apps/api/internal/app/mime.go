package app

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	netmail "net/mail"
	"net/smtp"
	"net/textproto"
	"sort"
	"strings"
	"time"
)

const smtpSessionTimeout = 45 * time.Second

type MIMEMessage struct {
	From        string
	FromName    string
	To          []string
	CC          []string
	BCC         []string
	Subject     string
	Text        string
	HTML        string
	MessageID   string
	Date        time.Time
	Attachments []AttachmentInput
	Headers     map[string]string
}

func BuildMIME(m MIMEMessage) ([]byte, error) {
	var buf bytes.Buffer
	writeHeader := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}
	writeHeader("From", formatAddressHeader(m.FromName, m.From))
	writeHeader("To", strings.Join(m.To, ", "))
	writeHeader("Cc", strings.Join(m.CC, ", "))
	writeHeader("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	writeHeader("Message-ID", m.MessageID)
	writeHeader("Date", m.Date.Format(time.RFC1123Z))
	writeHeader("MIME-Version", "1.0")
	for _, key := range sortedMIMEHeaderKeys(m.Headers) {
		if !validMIMEHeader(key, m.Headers[key]) {
			return nil, fmt.Errorf("invalid MIME header %q", key)
		}
		writeHeader(key, m.Headers[key])
	}

	mixed := multipart.NewWriter(&buf)
	writeHeader("Content-Type", `multipart/mixed; boundary="`+mixed.Boundary()+`"`)
	buf.WriteString("\r\n")

	var altBuf bytes.Buffer
	alt := multipart.NewWriter(&altBuf)
	textHeader := textprotoMIMEHeader(map[string]string{"Content-Type": `text/plain; charset="utf-8"`, "Content-Transfer-Encoding": "base64"})
	textPart, err := alt.CreatePart(textHeader)
	if err != nil {
		return nil, err
	}
	writeBase64(textPart, []byte(m.Text))
	htmlHeader := textprotoMIMEHeader(map[string]string{"Content-Type": `text/html; charset="utf-8"`, "Content-Transfer-Encoding": "base64"})
	htmlPart, err := alt.CreatePart(htmlHeader)
	if err != nil {
		return nil, err
	}
	writeBase64(htmlPart, []byte(m.HTML))
	if err := alt.Close(); err != nil {
		return nil, err
	}

	altMixedHeader := textprotoMIMEHeader(map[string]string{"Content-Type": `multipart/alternative; boundary="` + alt.Boundary() + `"`})
	altMixedPart, err := mixed.CreatePart(altMixedHeader)
	if err != nil {
		return nil, err
	}
	if _, err := altMixedPart.Write(altBuf.Bytes()); err != nil {
		return nil, err
	}

	for _, att := range m.Attachments {
		data, err := base64.StdEncoding.DecodeString(att.ContentBase64)
		if err != nil {
			return nil, err
		}
		contentType := att.ContentType
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		filename := mime.QEncoding.Encode("utf-8", att.Filename)
		h := textprotoMIMEHeader(map[string]string{
			"Content-Type":              contentType + `; name="` + filename + `"`,
			"Content-Disposition":       `attachment; filename="` + filename + `"`,
			"Content-Transfer-Encoding": "base64",
		})
		part, err := mixed.CreatePart(h)
		if err != nil {
			return nil, err
		}
		writeBase64(part, data)
	}
	if err := mixed.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sortedMIMEHeaderKeys(headers map[string]string) []string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func validMIMEHeader(key, value string) bool {
	key = strings.TrimSpace(key)
	if key == "" || strings.ContainsAny(key, "\r\n:") || strings.ContainsAny(value, "\r\n") {
		return false
	}
	for _, r := range key {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}

func formatAddressHeader(name, address string) string {
	address = strings.TrimSpace(address)
	name = strings.TrimSpace(name)
	if address == "" || name == "" || strings.EqualFold(name, address) {
		return address
	}
	return (&netmail.Address{Name: name, Address: address}).String()
}

func textprotoMIMEHeader(values map[string]string) textproto.MIMEHeader {
	h := textproto.MIMEHeader{}
	for k, v := range values {
		h.Set(k, v)
	}
	return h
}

func writeBase64(w io.Writer, data []byte) {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(encoded, data)
	for len(encoded) > 76 {
		_, _ = w.Write(encoded[:76])
		_, _ = w.Write([]byte("\r\n"))
		encoded = encoded[76:]
	}
	_, _ = w.Write(encoded)
	_, _ = w.Write([]byte("\r\n"))
}

func (a *App) sendSMTP(from string, recipients []string, mimeBytes []byte) error {
	return sendSMTPWithConfig(a.config(), from, recipients, mimeBytes)
}

func sendSMTPWithConfig(cfg Config, from string, recipients []string, mimeBytes []byte) error {
	return sendSMTPWithTLSMode(cfg, "", from, recipients, mimeBytes)
}

type smtpSendError struct {
	err          error
	retrySafe    bool
	failoverSafe bool
}

func (e *smtpSendError) Error() string { return e.err.Error() }
func (e *smtpSendError) Unwrap() error { return e.err }

func smtpPhaseError(err error, retrySafe bool) error {
	if err == nil {
		return nil
	}
	return &smtpSendError{err: err, retrySafe: retrySafe, failoverSafe: retrySafe}
}

func smtpCommandError(err error, phase string) error {
	if err == nil {
		return nil
	}
	retrySafe := false
	var protocolErr *textproto.Error
	if errors.As(err, &protocolErr) {
		retrySafe = protocolErr.Code >= 400 && protocolErr.Code < 500
	}
	return &smtpSendError{err: err, retrySafe: retrySafe, failoverSafe: phase == "auth"}
}

func smtpErrorRetrySafe(err error) bool {
	var phaseErr *smtpSendError
	return errors.As(err, &phaseErr) && phaseErr.retrySafe
}

func smtpErrorFailoverSafe(err error) bool {
	var phaseErr *smtpSendError
	return errors.As(err, &phaseErr) && phaseErr.failoverSafe
}

func smtpErrorAffectsRelay(err error) bool {
	if smtpErrorFailoverSafe(err) {
		return true
	}
	var protocolErr *textproto.Error
	return errors.As(err, &protocolErr) && (protocolErr.Code == 421 || protocolErr.Code == 451)
}

func smtpRetryDelay(err error, fallback time.Duration) time.Duration {
	var protocolErr *textproto.Error
	if errors.As(err, &protocolErr) && (protocolErr.Code == 421 || protocolErr.Code == 450 || protocolErr.Code == 451) && fallback < 5*time.Minute {
		return 5 * time.Minute
	}
	return fallback
}

func sendSMTPWithTLSMode(cfg Config, tlsMode, from string, recipients []string, mimeBytes []byte) error {
	addr := net.JoinHostPort(cfg.SMTPHost, cfg.SMTPPort)
	var auth smtp.Auth
	if cfg.SMTPUsername != "" {
		auth = smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPHost)
	}
	if tlsMode == "plain" || tlsMode == "" && !cfg.SMTPRequireTLS {
		return sendSMTPPlain(addr, cfg.SMTPHost, auth, from, recipients, mimeBytes)
	}
	if tlsMode == "tls" || tlsMode == "" && cfg.SMTPPort == "465" {
		return sendSMTPImplicitTLS(addr, cfg.SMTPHost, auth, from, recipients, mimeBytes)
	}
	return sendSMTPStartTLS(addr, cfg.SMTPHost, auth, from, recipients, mimeBytes)
}

func sendSMTPPlain(addr, host string, auth smtp.Auth, from string, recipients []string, mimeBytes []byte) error {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return smtpPhaseError(err, true)
	}
	_ = conn.SetDeadline(time.Now().Add(smtpSessionTimeout))
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return smtpPhaseError(err, true)
	}
	defer client.Close()
	return sendSMTPMessage(client, auth, from, recipients, mimeBytes)
}

func sendSMTPImplicitTLS(addr, host string, auth smtp.Auth, from string, recipients []string, mimeBytes []byte) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err != nil {
		return smtpPhaseError(err, true)
	}
	_ = conn.SetDeadline(time.Now().Add(smtpSessionTimeout))
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return smtpPhaseError(err, true)
	}
	defer client.Close()
	return sendSMTPMessage(client, auth, from, recipients, mimeBytes)
}

func sendSMTPStartTLS(addr, host string, auth smtp.Auth, from string, recipients []string, mimeBytes []byte) error {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return smtpPhaseError(err, true)
	}
	_ = conn.SetDeadline(time.Now().Add(smtpSessionTimeout))
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return smtpPhaseError(err, true)
	}
	defer client.Close()
	if ok, _ := client.Extension("STARTTLS"); !ok {
		return smtpPhaseError(errors.New("smtp server does not support STARTTLS"), true)
	}
	if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
		return smtpPhaseError(err, true)
	}
	return sendSMTPMessage(client, auth, from, recipients, mimeBytes)
}

func sendSMTPMessage(client *smtp.Client, auth smtp.Auth, from string, recipients []string, mimeBytes []byte) error {
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return smtpCommandError(err, "auth")
		}
	}
	if err := client.Mail(from); err != nil {
		return smtpCommandError(err, "mail")
	}
	for _, rcpt := range recipients {
		if err := client.Rcpt(rcpt); err != nil {
			return smtpCommandError(err, "recipient")
		}
	}
	wc, err := client.Data()
	if err != nil {
		return smtpCommandError(err, "data")
	}
	if _, err := wc.Write(mimeBytes); err != nil {
		_ = wc.Close()
		return smtpPhaseError(err, false)
	}
	if err := wc.Close(); err != nil {
		return smtpPhaseError(err, false)
	}
	// A successful DATA close is the SMTP acceptance point. A later QUIT
	// failure must not cause another relay to deliver the same message again.
	_ = client.Quit()
	return nil
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\n", "<br>")
	return s
}
