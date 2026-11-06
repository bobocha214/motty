package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
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

func TestBarkPutsTheTitleAndBodyInThePath(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if r.Method != http.MethodGet {
			t.Errorf("method = %s", r.Method)
		}
	}))
	defer server.Close()

	err := Send(context.Background(), server.Client(), Channel{Kind: Bark, Endpoint: server.URL + "/device"}, Event{
		Kind: "test", Title: "Motty 测试", Body: "这是一条测试消息",
	})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/device/Motty 测试/这是一条测试消息" {
		t.Fatalf("path = %q", path)
	}
}

func TestServerChanPostsTheFormItsEndpointTakes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			t.Errorf("request = %s %q", r.Method, r.Header.Get("Content-Type"))
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.PostForm.Get("title") != "测试" || r.PostForm.Get("desp") != "正文" {
			t.Errorf("form = %v", r.PostForm)
		}
	}))
	defer server.Close()

	if err := Send(context.Background(), server.Client(), Channel{Kind: ServerChan, Endpoint: server.URL + "/key.send"}, Event{
		Kind: "test", Title: "测试", Body: "正文",
	}); err != nil {
		t.Fatal(err)
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

func TestAChannelMustBeAnHTTPURL(t *testing.T) {
	for _, test := range []struct {
		channel Channel
		ok      bool
	}{
		{Channel{Kind: Webhook, Endpoint: "https://example.com/hook"}, true},
		{Channel{Kind: Bark, Endpoint: "http://127.0.0.1:8080/device"}, true},
		{Channel{Kind: Feishu, Endpoint: "https://open.feishu.cn/hook", Secret: "s"}, true},
		{Channel{Kind: DingTalk, Endpoint: "https://oapi.dingtalk.com/robot/send", Secret: "s"}, true},
		{Channel{Kind: WeCom, Endpoint: "https://qyapi.weixin.qq.com/send"}, true},
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
