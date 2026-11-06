package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestWebhookPostsTheEventAsJSON(t *testing.T) {
	var got struct {
		Kind  string `json:"kind"`
		Title string `json:"title"`
		Body  string `json:"body"`
		Time  string `json:"time"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("request = %s %q", r.Method, r.Header.Get("Content-Type"))
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("body %q: %v", raw, err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	at := time.Date(2026, 11, 2, 12, 0, 0, 0, time.FixedZone("CST", 8*3600))
	err := Send(context.Background(), server.Client(), Channel{Kind: Webhook, Endpoint: server.URL + "/hook/token"}, Event{
		Kind: "alert", Title: "磁盘告警", Body: "web-01 使用率 94%", Time: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "alert" || got.Title != "磁盘告警" || got.Body != "web-01 使用率 94%" || got.Time != at.Format(time.RFC3339) {
		t.Fatalf("payload = %+v", got)
	}
}

func TestFeishuSignsTheTimestampWithTheSecret(t *testing.T) {
	var got struct {
		Timestamp string `json:"timestamp"`
		Sign      string `json:"sign"`
		MsgType   string `json:"msg_type"`
		Content   struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	if err := Send(context.Background(), server.Client(), Channel{Kind: Feishu, Endpoint: server.URL + "/hook", Secret: "s3cret"}, Event{
		Title: "磁盘告警", Body: "web-01 使用率 94%",
	}); err != nil {
		t.Fatal(err)
	}
	if got.MsgType != "text" || !strings.Contains(got.Content.Text, "磁盘告警") || !strings.Contains(got.Content.Text, "web-01") {
		t.Fatalf("payload = %+v", got)
	}
	mac := hmac.New(sha256.New, []byte(got.Timestamp+"\ns3cret"))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if got.Timestamp == "" || got.Sign != want {
		t.Fatalf("timestamp %q sign %q, want %q", got.Timestamp, got.Sign, want)
	}
}

func TestFeishuWithoutASecretSendsNoSignature(t *testing.T) {
	var got map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	if err := Send(context.Background(), server.Client(), Channel{Kind: Feishu, Endpoint: server.URL + "/hook"}, Event{Title: "t"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["timestamp"]; ok {
		t.Fatalf("an unsigned Feishu bot got a timestamp: %v", got)
	}
	if _, ok := got["sign"]; ok {
		t.Fatalf("an unsigned Feishu bot got a signature: %v", got)
	}
}

func TestDingTalkSignsTheMillisecondTimestampInTheQuery(t *testing.T) {
	var query url.Values
	var got struct {
		MsgType  string `json:"msgtype"`
		Markdown struct {
			Title string `json:"title"`
			Text  string `json:"text"`
		} `json:"markdown"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query()
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	if err := Send(context.Background(), server.Client(), Channel{Kind: DingTalk, Endpoint: server.URL + "/robot/send?access_token=t", Secret: "s3cret"}, Event{
		Title: "磁盘告警", Body: "web-01 使用率 94%",
	}); err != nil {
		t.Fatal(err)
	}
	timestamp, sign := query.Get("timestamp"), query.Get("sign")
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write([]byte(timestamp + "\ns3cret"))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if timestamp == "" || sign != want {
		t.Fatalf("timestamp %q sign %q, want %q", timestamp, sign, want)
	}
	if query.Get("access_token") != "t" {
		t.Fatalf("the robot token was lost: %v", query)
	}
	if got.MsgType != "markdown" || got.Markdown.Title != "磁盘告警" || !strings.Contains(got.Markdown.Text, "web-01") {
		t.Fatalf("payload = %+v", got)
	}
}

func TestWeComPostsMarkdownWithoutSigning(t *testing.T) {
	var got struct {
		MsgType  string `json:"msgtype"`
		Markdown struct {
			Content string `json:"content"`
		} `json:"markdown"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	if err := Send(context.Background(), server.Client(), Channel{Kind: WeCom, Endpoint: server.URL + "/send?key=k"}, Event{
		Title: "磁盘告警", Body: "web-01 使用率 94%",
	}); err != nil {
		t.Fatal(err)
	}
	if got.MsgType != "markdown" || !strings.Contains(got.Markdown.Content, "**磁盘告警**") || !strings.Contains(got.Markdown.Content, "web-01") {
		t.Fatalf("payload = %+v", got)
	}
}

// TestEmailSendPlain sets up a minimal plain SMTP listener that accepts a DATA
// command without STARTTLS. This exercises sendEmail's plain-TCP path with no
// STARTTLS extension advertised.
func TestEmailSendPlain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var received []byte
	done := make(chan struct{})

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = conn.Write([]byte("220 localhost ESMTP ready\r\n"))
		buf := make([]byte, 8192)
		// Read until "DATA" command
		state := "init"
		for {
			n, _ := conn.Read(buf)
			if n == 0 {
				return
			}
			got := string(buf[:n])
			switch {
			case strings.HasPrefix(got, "EHLO") || strings.HasPrefix(got, "HELO"):
				// Multi-line EHLO: extensions prefixed with 250-
				_, _ = conn.Write([]byte("250-localhost\r\n250 AUTH PLAIN\r\n"))
				state = "ehlo"
			case strings.HasPrefix(got, "AUTH"):
				// AUTH PLAIN sends credentials in one command line
				_, _ = conn.Write([]byte("235 Authenticated\r\n"))
				state = "auth"
			case strings.HasPrefix(got, "MAIL FROM"):
				_, _ = conn.Write([]byte("250 OK\r\n"))
				state = "mail"
			case strings.HasPrefix(got, "RCPT TO"):
				_, _ = conn.Write([]byte("250 OK\r\n"))
				state = "rcpt"
			case strings.HasPrefix(got, "DATA"):
				_, _ = conn.Write([]byte("354 End data with <CR><LF>.<CR><LF>\r\n"))
				state = "data"
			case state == "data" && strings.Contains(got, "\r\n.\r\n"):
				// End of data — QUIT comes next
				received = append(received, []byte(got)...)
				_, _ = conn.Write([]byte("250 OK\r\n"))
			case strings.HasPrefix(got, "QUIT"):
				_, _ = conn.Write([]byte("221 Bye\r\n"))
				close(done)
				return
			case state == "data":
				received = append(received, []byte(got)...)
			}
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	cfg := EmailConfig{
		Host:     "127.0.0.1",
		Port:     addr.Port,
		Username: "alice",
		From:     "alice@example.com",
		To:       []string{"bob@example.com"},
	}
	raw, _ := json.Marshal(cfg)

	err = Send(context.Background(), nil, Channel{
		Kind: Email, Endpoint: string(raw), Secret: "pw",
	}, Event{Title: "磁盘告警", Body: "web-01 使用率 94%"})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("SMTP server didn't finish — check protocol flow")
	}

	got := string(received)
	if !strings.Contains(got, "From: alice@example.com") {
		t.Errorf("missing From header in:\n%s", got)
	}
	if !strings.Contains(got, "To: bob@example.com") {
		t.Errorf("missing To header in:\n%s", got)
	}
	if !strings.Contains(got, "web-01 使用率 94%") {
		t.Errorf("missing body in:\n%s", got)
	}
}

func TestEmailValidateRejectsMissingFields(t *testing.T) {
	for _, test := range []struct {
		name string
		cfg  EmailConfig
		ok   bool
	}{
		{"valid", EmailConfig{Host: "smtp.example.com", Port: 587, Username: "u", From: "a@b.com", To: []string{"c@d.com"}}, true},
		{"empty host", EmailConfig{Port: 587, Username: "u", From: "a@b.com", To: []string{"c@d.com"}}, false},
		{"port 0", EmailConfig{Host: "h", Port: 0, Username: "u", From: "a@b.com", To: []string{"c@d.com"}}, false},
		{"port too big", EmailConfig{Host: "h", Port: 70000, Username: "u", From: "a@b.com", To: []string{"c@d.com"}}, false},
		{"empty from", EmailConfig{Host: "h", Port: 587, Username: "u", To: []string{"c@d.com"}}, false},
		{"no recipients", EmailConfig{Host: "h", Port: 587, Username: "u", From: "a@b.com"}, false},
		{"empty recipient", EmailConfig{Host: "h", Port: 587, Username: "u", From: "a@b.com", To: []string{""}}, false},
	} {
		raw, _ := json.Marshal(test.cfg)
		err := (Channel{Kind: Email, Endpoint: string(raw)}).Validate()
		if (err == nil) != test.ok {
			t.Errorf("%s: Validate() err=%v", test.name, err)
		}
	}
}

func TestAChannelMustBeAnHTTPURL(t *testing.T) {
	for _, test := range []struct {
		channel Channel
		ok      bool
	}{
		{Channel{Kind: Webhook, Endpoint: "https://example.com/hook"}, true},
		{Channel{Kind: Feishu, Endpoint: "https://open.feishu.cn/hook", Secret: "s"}, true},
		{Channel{Kind: DingTalk, Endpoint: "https://oapi.dingtalk.com/robot/send", Secret: "s"}, true},
		{Channel{Kind: WeCom, Endpoint: "https://qyapi.weixin.qq.com/send"}, true},
		{Channel{Kind: Email, Endpoint: `{"host":"smtp.example.com","port":587,"username":"u","from":"a@b.com","to":["c@d.com"]}`}, true},
		{Channel{Kind: Feishu, Endpoint: "https://open.feishu.cn/hook", Secret: strings.Repeat("s", maxSecret+1)}, false},
		{Channel{Kind: Webhook, Endpoint: ""}, false},
		{Channel{Kind: Webhook, Endpoint: "example.com/hook"}, false},
		{Channel{Kind: Webhook, Endpoint: "ftp://example.com/hook"}, false},
		{Channel{Kind: Webhook, Endpoint: "https://"}, false},
		{Channel{Kind: Kind(99), Endpoint: "https://example.com/hook"}, false},
	} {
		err := test.channel.Validate()
		if (err == nil) != test.ok {
			t.Errorf("%+v: %v", test.channel, err)
		}
	}
}

func TestARefusalNamesTheHostNotTheToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad token", http.StatusUnauthorized)
	}))
	defer server.Close()

	err := Send(context.Background(), server.Client(), Channel{Kind: Webhook, Endpoint: server.URL + "/hook/secret-token"}, Event{Title: "t"})
	if err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "bad token") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("the error leaked the token: %v", err)
	}
}

func TestRedactKeepsOnlyTheHost(t *testing.T) {
	if got := Redact("https://api.example.com:8443/hook/secret?token=abc"); got != "https://api.example.com:8443/…" {
		t.Fatalf("redacted = %q", got)
	}
	if got := Redact("not a url"); got != "(invalid endpoint)" {
		t.Fatalf("redacted = %q", got)
	}
}

func TestKindFromStringHandlesRemovedKinds(t *testing.T) {
	// Bark and ServerChan strings should no longer parse — saved configs using
	// them get dropped by restoreAlertChannels, which is the desired behaviour.
	if _, ok := KindFromString("bark"); ok {
		t.Error("bark should no longer be a valid kind")
	}
	if _, ok := KindFromString("serverchan"); ok {
		t.Error("serverchan should no longer be a valid kind")
	}
	// Email should be valid.
	if k, ok := KindFromString("email"); !ok || k != Email {
		t.Errorf("email parse = %v %v", k, ok)
	}
}
