// Package notify delivers one message to an external push service. The caller
// decides when to send and what the message says; this package only knows the
// request shapes and validates what the user typed. Endpoints and signing
// secrets carry tokens, so errors and logs use Redact instead of the URL.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Kind is the shape of a push service's API.
type Kind uint8

// The kinds this build speaks.
const (
	Webhook Kind = iota
	Feishu
	DingTalk
	WeCom
	Email
)

func (kind Kind) String() string {
	switch kind {
	case Feishu:
		return "feishu"
	case DingTalk:
		return "dingtalk"
	case WeCom:
		return "wecom"
	case Email:
		return "email"
	}
	return "webhook"
}

// Signed reports whether the kind can use a signing secret beside its webhook
// address. WeCom puts its key in the URL and signs nothing.
func (kind Kind) Signed() bool { return kind == Feishu || kind == DingTalk }

// KindFromString reads a saved kind. Unknown values are refused rather than
// silently becoming a webhook.
func KindFromString(value string) (Kind, bool) {
	switch value {
	case "webhook":
		return Webhook, true
	case "feishu":
		return Feishu, true
	case "dingtalk":
		return DingTalk, true
	case "wecom":
		return WeCom, true
	case "email":
		return Email, true
	}
	return 0, false
}

// Channel is one saved destination. Endpoint is the full URL, including the
// token or device key the service put in it; it belongs in the vault, not in the
// state file. For Email kind, Endpoint stores the EmailConfig as JSON.
type Channel struct {
	Kind     Kind
	Endpoint string
	// Secret is the optional signing key of a Feishu or DingTalk robot, or the
	// SMTP password for an Email channel. It stays in the vault beside the
	// endpoint.
	Secret string
}

// Event is what a push says.
type Event struct {
	// Kind is "test" for the settings page's test button and "alert" for a
	// monitoring rule.
	Kind  string
	Title string
	Body  string
	Time  time.Time
}

// Errors callers act on.
var (
	ErrInvalidEndpoint = errors.New("notify: invalid endpoint")
	ErrInvalidSecret   = errors.New("notify: invalid signing secret")
	ErrUnknownKind     = errors.New("notify: unknown channel kind")
)

const (
	maxEndpoint   = 2048
	maxSecret     = 256
	maxTitleRunes = 120
	maxBodyRunes  = 900
	maxIMBody     = 700
	maxReplyBytes = 8 << 10
)

// EmailConfig is how a user describes one SMTP destination. It is serialised
// into Channel.Endpoint as JSON so that the password (Channel.Secret) can
// remain in a separate vault entry.
type EmailConfig struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Username string   `json:"username"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	// Port is kept as an int so the caller does not have to parse ":587"
	// themselves. Host should be a bare hostname or IP, not a URL.
}

// ParseEmailConfig reads the JSON the UI stores.
func ParseEmailConfig(raw string) (EmailConfig, error) {
	var cfg EmailConfig
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &cfg); err != nil {
		return cfg, fmt.Errorf("invalid email config: %w", err)
	}
	if cfg.Host == "" {
		return cfg, errors.New("invalid email config: host is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return cfg, errors.New("invalid email config: port must be 1-65535")
	}
	if cfg.From == "" {
		return cfg, errors.New("invalid email config: from address is required")
	}
	if len(cfg.To) == 0 {
		return cfg, errors.New("invalid email config: at least one recipient is required")
	}
	for _, to := range cfg.To {
		if strings.TrimSpace(to) == "" {
			return cfg, errors.New("invalid email config: empty recipient")
		}
	}
	return cfg, nil
}

// Validate reports whether a channel can be sent to. It checks the scheme and
// host, not that the service exists.
func (channel Channel) Validate() error {
	if channel.Kind > Email {
		return ErrUnknownKind
	}
	if channel.Kind == Email {
		_, err := ParseEmailConfig(channel.Endpoint)
		return err
	}
	endpoint := strings.TrimSpace(channel.Endpoint)
	if endpoint == "" || len(endpoint) > maxEndpoint {
		return ErrInvalidEndpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return ErrInvalidEndpoint
	}
	if len(channel.Secret) > maxSecret {
		return ErrInvalidSecret
	}
	return nil
}

// Send delivers one event. A nil client uses a ten-second timeout. Callers run
// this off the window thread; it blocks until the service answers or the
// context ends.
func Send(ctx context.Context, client *http.Client, channel Channel, event Event) error {
	if err := channel.Validate(); err != nil {
		return err
	}
	if event.Time.IsZero() {
		event.Time = time.Now()
	}
	httpClient := client
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	switch channel.Kind {
	case Feishu:
		return sendFeishu(ctx, httpClient, channel, event)
	case DingTalk:
		return sendDingTalk(ctx, httpClient, channel, event)
	case WeCom:
		return sendWeCom(ctx, httpClient, channel.Endpoint, event)
	case Email:
		return sendEmail(ctx, channel, event)
	default:
		return sendWebhook(ctx, httpClient, channel.Endpoint, event)
	}
}

func sendWebhook(ctx context.Context, client *http.Client, endpoint string, event Event) error {
	payload := struct {
		Kind  string `json:"kind"`
		Title string `json:"title"`
		Body  string `json:"body"`
		Time  string `json:"time"`
	}{Kind: event.Kind, Title: truncate(event.Title, maxTitleRunes), Body: truncate(event.Body, maxBodyRunes), Time: event.Time.Format(time.RFC3339)}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "motty")
	return do(client, request, endpoint)
}

// sendFeishu posts a text message to a custom bot. The bot's optional secret
// signs the timestamp with HMAC-SHA256, where the string to sign is the key.
func sendFeishu(ctx context.Context, client *http.Client, channel Channel, event Event) error {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	payload := struct {
		Timestamp string `json:"timestamp,omitempty"`
		Sign      string `json:"sign,omitempty"`
		MsgType   string `json:"msg_type"`
		Content   struct {
			Text string `json:"text"`
		} `json:"content"`
	}{MsgType: "text"}
	if channel.Secret != "" {
		payload.Timestamp = timestamp
		payload.Sign = feishuSign(timestamp, channel.Secret)
	}
	payload.Content.Text = eventText(event)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, channel.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "motty")
	return do(client, request, channel.Endpoint)
}

// sendDingTalk posts a markdown message. The optional secret signs the
// millisecond timestamp as a query parameter.
func sendDingTalk(ctx context.Context, client *http.Client, channel Channel, event Event) error {
	endpoint := channel.Endpoint
	if channel.Secret != "" {
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return ErrInvalidEndpoint
		}
		query := parsed.Query()
		query.Set("timestamp", timestamp)
		query.Set("sign", dingTalkSign(timestamp, channel.Secret))
		parsed.RawQuery = query.Encode()
		endpoint = parsed.String()
	}
	payload := struct {
		MsgType  string `json:"msgtype"`
		Markdown struct {
			Title string `json:"title"`
			Text  string `json:"text"`
		} `json:"markdown"`
	}{MsgType: "markdown"}
	payload.Markdown.Title = truncate(event.Title, 40)
	payload.Markdown.Text = eventMarkdown(event)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "motty")
	return do(client, request, channel.Endpoint)
}

// sendWeCom posts a markdown message. Its group robot carries the key in the
// webhook URL and signs nothing.
func sendWeCom(ctx context.Context, client *http.Client, endpoint string, event Event) error {
	payload := struct {
		MsgType  string `json:"msgtype"`
		Markdown struct {
			Content string `json:"content"`
		} `json:"markdown"`
	}{MsgType: "markdown"}
	payload.Markdown.Content = eventMarkdown(event)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "motty")
	return do(client, request, endpoint)
}

// sendEmail delivers a plain-text email via SMTP. It picks between two modes:
// port 465 uses TLS-on-connect (smtps); every other port (25, 587, custom)
// starts with plain SMTP and then upgrades with STARTTLS if the server
// advertises it.
func sendEmail(ctx context.Context, channel Channel, event Event) error {
	cfg, err := ParseEmailConfig(channel.Endpoint)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	subject := truncate(event.Title, maxTitleRunes)
	body := eventText(event)
	subject = mimeEncode(subject)

	message := "From: " + cfg.From + "\r\n" +
		"To: " + strings.Join(cfg.To, ", ") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n" +
		"Date: " + event.Time.Format(time.RFC1123Z) + "\r\n\r\n" +
		body + "\r\n"

	// 465 = TLS on connect (smtps).
	if cfg.Port == 465 {
		tlsConfig := &tls.Config{ServerName: cfg.Host}
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("notify: email %s: %w", cfg.Host, err)
		}
		client, err := smtp.NewClient(conn, cfg.Host)
		if err != nil {
			return fmt.Errorf("notify: email %s: %w", cfg.Host, err)
		}
		defer client.Close()
		return smtpSend(ctx, client, cfg, channel.Secret, message)
	}

	// Plain SMTP with optional STARTTLS.
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("notify: email %s: %w", cfg.Host, err)
	}
	deadline, ok := ctx.Deadline()
	if ok {
		_ = conn.SetDeadline(deadline)
	}
	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("notify: email %s: %w", cfg.Host, err)
	}
	defer client.Close()

	if err := client.Hello("motty"); err != nil {
		return fmt.Errorf("notify: email hello: %w", err)
	}
	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsConfig := &tls.Config{ServerName: cfg.Host}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("notify: email %s STARTTLS: %w", cfg.Host, err)
		}
	}
	return smtpSend(ctx, client, cfg, channel.Secret, message)
}

func smtpSend(ctx context.Context, client *smtp.Client, cfg EmailConfig, password, message string) error {
	if password != "" {
		auth := smtp.PlainAuth("", cfg.Username, password, cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("notify: email auth: %w", err)
		}
	}
	if err := client.Mail(cfg.From); err != nil {
		return fmt.Errorf("notify: email from: %w", err)
	}
	for _, to := range cfg.To {
		if err := client.Rcpt(strings.TrimSpace(to)); err != nil {
			return fmt.Errorf("notify: email rcpt: %w", err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("notify: email data: %w", err)
	}
	if _, err := w.Write([]byte(message)); err != nil {
		_ = w.Close()
		return fmt.Errorf("notify: email write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("notify: email close: %w", err)
	}
	return client.Quit()
}

// mimeEncode RFC 2047-encodes an email header value that contains non-ASCII
// characters. Plain ASCII passes through untouched.
func mimeEncode(value string) string {
	if asciiOnly(value) {
		return value
	}
	return "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(value)) + "?="
}

func asciiOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// eventText is the plain form of a message.
func eventText(event Event) string {
	title := truncate(event.Title, maxTitleRunes)
	body := truncate(event.Body, maxIMBody)
	if title == "" {
		return body
	}
	if body == "" {
		return title
	}
	return title + "\n\n" + body
}

// eventMarkdown is the form the IM robots show.
func eventMarkdown(event Event) string {
	title := truncate(event.Title, maxTitleRunes)
	body := truncate(event.Body, maxIMBody)
	switch {
	case title == "":
		return body
	case body == "":
		return "**" + title + "**"
	}
	return "**" + title + "**\n\n" + body
}

// feishuSign follows the custom bot's rule: HMAC-SHA256 with the string
// "<timestamp>\n<secret>" as its key and an empty message.
func feishuSign(timestamp, secret string) string {
	mac := hmac.New(sha256.New, []byte(timestamp+"\n"+secret))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// dingTalkSign follows the robot's rule: HMAC-SHA256 with the secret as its key
// and "<timestamp>\n<secret>" as the message.
func dingTalkSign(timestamp, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "\n" + secret))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// do reads a bounded reply and turns a refusal into an error that names the
// service's host, never the token in its path or query.
func do(client *http.Client, request *http.Request, endpoint string) error {
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("notify: %s: %w", Redact(endpoint), err)
	}
	defer response.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(response.Body, maxReplyBytes))
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	detail := strings.Join(strings.Fields(string(reply)), " ")
	if len(detail) > 200 {
		detail = detail[:200] + "…"
	}
	if detail == "" {
		return fmt.Errorf("notify: %s returned %s", Redact(endpoint), response.Status)
	}
	return fmt.Errorf("notify: %s returned %s: %s", Redact(endpoint), response.Status, detail)
}

// Redact is an endpoint safe to show or log: scheme, host and a marker in place
// of the token-bearing path and query.
func Redact(endpoint string) string {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Host == "" {
		return "(invalid endpoint)"
	}
	return parsed.Scheme + "://" + parsed.Host + "/…"
}

// truncate bounds a field by runes so a long terminal line cannot make the URL
// form of a request arbitrarily large.
func truncate(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "…"
}
