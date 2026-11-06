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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	Bark
	ServerChan
	Feishu
	DingTalk
	WeCom
)

func (kind Kind) String() string {
	switch kind {
	case Bark:
		return "bark"
	case ServerChan:
		return "serverchan"
	case Feishu:
		return "feishu"
	case DingTalk:
		return "dingtalk"
	case WeCom:
		return "wecom"
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
	case "bark":
		return Bark, true
	case "serverchan":
		return ServerChan, true
	case "feishu":
		return Feishu, true
	case "dingtalk":
		return DingTalk, true
	case "wecom":
		return WeCom, true
	}
	return 0, false
}

// Channel is one saved destination. Endpoint is the full URL, including the
// token or device key the service put in it; it belongs in the vault, not in the
// state file.
type Channel struct {
	Kind     Kind
	Endpoint string
	// Secret is the optional signing key of a Feishu or DingTalk robot. It stays
	// in the vault beside the endpoint.
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

// Validate reports whether a channel can be sent to. It checks the scheme and
// host, not that the service exists.
func (channel Channel) Validate() error {
	if channel.Kind > WeCom {
		return ErrUnknownKind
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
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if event.Time.IsZero() {
		event.Time = time.Now()
	}
	switch channel.Kind {
	case Bark:
		return sendBark(ctx, client, channel.Endpoint, event)
	case ServerChan:
		return sendServerChan(ctx, client, channel.Endpoint, event)
	case Feishu:
		return sendFeishu(ctx, client, channel, event)
	case DingTalk:
		return sendDingTalk(ctx, client, channel, event)
	case WeCom:
		return sendWeCom(ctx, client, channel.Endpoint, event)
	default:
		return sendWebhook(ctx, client, channel.Endpoint, event)
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

// sendBark uses Bark's path form: /<device key>/<title>/<body>. The endpoint the
// user saved is the part up to the key.
func sendBark(ctx context.Context, client *http.Client, endpoint string, event Event) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return ErrInvalidEndpoint
	}
	// JoinPath escapes each segment, so a slash in the message cannot become a
	// path boundary.
	parsed = parsed.JoinPath(truncate(event.Title, maxTitleRunes), truncate(event.Body, maxBodyRunes))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "motty")
	return do(client, request, endpoint)
}

// sendServerChan posts the form its .send endpoint takes.
func sendServerChan(ctx context.Context, client *http.Client, endpoint string, event Event) error {
	form := url.Values{}
	form.Set("title", truncate(event.Title, maxTitleRunes))
	form.Set("desp", truncate(event.Body, maxBodyRunes))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
