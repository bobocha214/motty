package workbench

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vivaui/viva/text"
	"github.com/vivaui/viva/ui"
	"motty/internal/notify"
)

func openAlertSettings(state *State) {
	state.Click(hitSettings)
	state.selectSettingsCategory(settingsNotifications)
}

func addAlertChannel(t *testing.T, state *State, name string, kind notify.Kind, endpoint string) {
	t.Helper()
	openAlertSettings(state)
	state.Click(hitAlertAdd)
	if state.modal != modalAlertChannel {
		t.Fatalf("modal = %d", state.modal)
	}
	switch kind {
	case notify.Email:
		state.Click(hitAlertKindEmail)
	case notify.Feishu:
		state.Click(hitAlertKindFeishu)
	case notify.DingTalk:
		state.Click(hitAlertKindDing)
	case notify.WeCom:
		state.Click(hitAlertKindWeCom)
	}
	typeInto(state, hitAlertName, name)
	typeInto(state, hitAlertEndpoint, endpoint)
	state.Click(hitAlertSave)
}

func addSignedAlertChannel(t *testing.T, state *State, name string, kind notify.Kind, endpoint, secret string) {
	t.Helper()
	openAlertSettings(state)
	state.Click(hitAlertAdd)
	if state.modal != modalAlertChannel {
		t.Fatalf("modal = %d", state.modal)
	}
	switch kind {
	case notify.Feishu:
		state.Click(hitAlertKindFeishu)
	case notify.DingTalk:
		state.Click(hitAlertKindDing)
	}
	typeInto(state, hitAlertName, name)
	typeInto(state, hitAlertEndpoint, endpoint)
	typeInto(state, hitAlertSecret, secret)
	state.Click(hitAlertSave)
}

func TestAFeishuChannelKeepsItsSigningSecretInTheVault(t *testing.T) {
	_, options := newWorld(t)
	state := newTestState(t, options)
	addSignedAlertChannel(t, state, "Ops", notify.Feishu, "https://open.feishu.cn/hook/token", "sign-me")
	if state.modal != modalNone || len(state.alertChannels) != 1 || state.alertChannels[0].Kind != notify.Feishu {
		t.Fatalf("modal %d, channels %+v", state.modal, state.alertChannels)
	}
	id := state.alertChannels[0].ID
	if secret := state.alertChannelSigningSecret(id); secret != "sign-me" {
		t.Fatalf("signing secret = %q", secret)
	}
	if endpoint, found, _ := state.secrets.vault.Get(alertChannelSecretName(id)); !found || endpoint != "https://open.feishu.cn/hook/token" {
		t.Fatalf("endpoint = %q %v", endpoint, found)
	}
	saved, _, err := loadState(state.options.StatePath)
	if err != nil || strings.Contains(string(mustJSON(t, saved)), "sign-me") {
		t.Fatalf("the signing secret reached the state file: %v", err)
	}
	restored := newTestState(t, options)
	if len(restored.alertChannels) != 1 || restored.alertChannelSigningSecret(restored.alertChannels[0].ID) != "sign-me" {
		t.Fatalf("restored = %+v", restored.alertChannels)
	}
}

func TestEditingAFeishuChannelWithoutASecretKeepsIt(t *testing.T) {
	_, options := newWorld(t)
	state := newTestState(t, options)
	addSignedAlertChannel(t, state, "Ops", notify.Feishu, "https://open.feishu.cn/hook/token", "sign-me")
	id := state.alertChannels[0].ID
	state.Click(hitAlertEditList.At(0))
	state.alertForm.name = *text.NewEditor("Ops 2")
	state.Click(hitAlertSave)
	if state.modal != modalNone || state.alertChannels[0].Name != "Ops 2" {
		t.Fatalf("modal %d, channels %+v", state.modal, state.alertChannels)
	}
	if secret := state.alertChannelSigningSecret(id); secret != "sign-me" {
		t.Fatalf("signing secret = %q", secret)
	}
}

func TestChangingKindAwayFromSigningForgetsTheSecret(t *testing.T) {
	_, options := newWorld(t)
	state := newTestState(t, options)
	addSignedAlertChannel(t, state, "Ops", notify.Feishu, "https://open.feishu.cn/hook/token", "sign-me")
	id := state.alertChannels[0].ID
	state.Click(hitAlertEditList.At(0))
	state.Click(hitAlertKindWeCom)
	typeInto(state, hitAlertEndpoint, "https://qyapi.weixin.qq.com/send?key=k")
	state.Click(hitAlertSave)
	if state.modal != modalNone || state.alertChannels[0].Kind != notify.WeCom {
		t.Fatalf("modal %d, channels %+v", state.modal, state.alertChannels)
	}
	if secret := state.alertChannelSigningSecret(id); secret != "" {
		t.Fatalf("the old signing secret survived: %q", secret)
	}
}

func TestAnOverlongSigningSecretIsRefused(t *testing.T) {
	_, options := newWorld(t)
	state := newTestState(t, options)
	openAlertSettings(state)
	state.Click(hitAlertAdd)
	state.Click(hitAlertKindFeishu)
	typeInto(state, hitAlertName, "Ops")
	typeInto(state, hitAlertEndpoint, "https://open.feishu.cn/hook/token")
	typeInto(state, hitAlertSecret, strings.Repeat("s", maxAlertSecret+1))
	state.Click(hitAlertSave)
	if state.modal != modalAlertChannel || state.alertForm.dialogError != state.messages.Tools.NotifyErrSecret {
		t.Fatalf("modal %d, error %q", state.modal, state.alertForm.dialogError)
	}
}

func TestThePushChannelPageAndDialogPaintTheirControls(t *testing.T) {
	_, options := newWorld(t)
	state := newTestState(t, options)
	openAlertSettings(state)
	var canvas ui.Canvas
	state.Paint(&canvas, ui.Size{Width: 1400, Height: 900})
	if _, ok := hitByID(&canvas, hitAlertAdd); !ok {
		t.Fatal("the empty page does not offer Add channel")
	}
	state.Click(hitAlertAdd)
	canvas.Reset()
	state.Paint(&canvas, ui.Size{Width: 1400, Height: 900})
	for _, id := range []ui.ID{hitAlertKindWebhook, hitAlertKindFeishu, hitAlertKindDing, hitAlertKindWeCom, hitAlertKindEmail, hitAlertName, hitAlertEndpoint, hitAlertTest, hitAlertSave} {
		if _, ok := hitByID(&canvas, id); !ok {
			t.Errorf("the dialog does not paint control %d", id)
		}
	}
	if _, ok := hitByID(&canvas, hitAlertSecret); ok {
		t.Fatal("an unsigned channel shows a signing secret field")
	}
	state.Click(hitAlertKindFeishu)
	canvas.Reset()
	state.Paint(&canvas, ui.Size{Width: 1400, Height: 900})
	if _, ok := hitByID(&canvas, hitAlertSecret); !ok {
		t.Fatal("a Feishu channel does not show a signing secret field")
	}
	state.Click(hitAlertCancel)
	addAlertChannel(t, state, "Ops", notify.Webhook, "https://hooks.example.com/secret")
	canvas.Reset()
	state.Paint(&canvas, ui.Size{Width: 1400, Height: 900})
	if _, ok := hitByID(&canvas, hitAlertEditList.At(0)); !ok {
		t.Fatal("the saved channel is not in the page")
	}
	if _, ok := hitByID(&canvas, hitAlertTestList.At(0)); !ok {
		t.Fatal("the saved channel has no test button")
	}
}

func TestTheTestButtonSendsAMessageToTheChannel(t *testing.T) {
	requests := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requests <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	_, options := newWorld(t)
	state := newTestState(t, options)
	addAlertChannel(t, state, "Ops", notify.Webhook, server.URL+"/hook")
	state.Click(hitAlertTestList.At(0))
	sent := false
	waitFor(t, state, func() bool {
		select {
		case <-requests:
			sent = true
		default:
		}
		return sent && state.status == state.messages.Tools.NotifyTestSent
	})
}

func TestAPushChannelKeepsItsTokenInTheVault(t *testing.T) {
	_, options := newWorld(t)
	state := newTestState(t, options)
	addAlertChannel(t, state, "Ops", notify.Webhook, "https://api.example.com/device-key")
	if state.modal != modalNone || len(state.alertChannels) != 1 {
		t.Fatalf("modal %d, channels %+v", state.modal, state.alertChannels)
	}
	channel := state.alertChannels[0]
	if channel.ID == 0 || channel.Name != "Ops" || channel.Kind != notify.Webhook {
		t.Fatalf("channel = %+v", channel)
	}
	endpoint, found, err := state.secrets.vault.Get(alertChannelSecretName(channel.ID))
	if err != nil || !found || endpoint != "https://api.example.com/device-key" {
		t.Fatalf("vault = %q %v %v", endpoint, found, err)
	}
	saved, _, err := loadState(state.options.StatePath)
	if err != nil || len(saved.AlertChannels) != 1 || saved.AlertChannels[0].Name != "Ops" || saved.AlertChannels[0].Kind != "webhook" {
		t.Fatalf("saved channel = %+v %v", saved.AlertChannels, err)
	}
	if strings.Contains(string(mustJSON(t, saved)), "device-key") {
		t.Fatal("the endpoint was written to the state file")
	}

	restored := newTestState(t, options)
	if len(restored.alertChannels) != 1 || restored.alertChannels[0].Name != "Ops" || restored.alertChannels[0].Kind != notify.Webhook {
		again, _, _ := loadState(options.StatePath)
		t.Fatalf("restored = %+v (disk %+v, outcome %q)", restored.alertChannels, again.AlertChannels, restored.stateFileOutcome)
	}
	if restored.alertChannels[0].description != restored.messages.Tools.NotifyKindWebhook {
		t.Fatalf("description = %q", restored.alertChannels[0].description)
	}
}

func TestAPushChannelRefusesAnAddressThatIsNotHTTP(t *testing.T) {
	_, options := newWorld(t)
	state := newTestState(t, options)
	openAlertSettings(state)
	state.Click(hitAlertAdd)
	typeInto(state, hitAlertName, "Ops")
	typeInto(state, hitAlertEndpoint, "api.example.com/hook")
	state.Click(hitAlertSave)
	if state.modal != modalAlertChannel || state.alertForm.dialogError != state.messages.Tools.NotifyErrEndpoint {
		t.Fatalf("modal %d, error %q", state.modal, state.alertForm.dialogError)
	}
	if len(state.alertChannels) != 0 {
		t.Fatalf("channels = %+v", state.alertChannels)
	}
}

func TestEditingWithoutAnAddressKeepsTheSavedOne(t *testing.T) {
	_, options := newWorld(t)
	state := newTestState(t, options)
	addAlertChannel(t, state, "Ops", notify.Webhook, "https://hooks.example.com/secret")
	state.Click(hitAlertEditList.At(0))
	if state.modal != modalAlertChannel || state.alertForm.name.String() != "Ops" {
		t.Fatalf("modal %d, name %q", state.modal, state.alertForm.name.String())
	}
	state.alertForm.name = *text.NewEditor("Ops 2")
	state.Click(hitAlertSave)
	if state.modal != modalNone || len(state.alertChannels) != 1 || state.alertChannels[0].Name != "Ops 2" {
		t.Fatalf("modal %d, channels %+v", state.modal, state.alertChannels)
	}
	endpoint, found, err := state.secrets.vault.Get(alertChannelSecretName(state.alertChannels[0].ID))
	if err != nil || !found || endpoint != "https://hooks.example.com/secret" {
		t.Fatalf("endpoint = %q %v %v", endpoint, found, err)
	}
}

func TestChangingTheKindNeedsTheAddressAgain(t *testing.T) {
	_, options := newWorld(t)
	state := newTestState(t, options)
	addAlertChannel(t, state, "Ops", notify.Webhook, "https://hooks.example.com/secret")
	state.Click(hitAlertEditList.At(0))
	state.Click(hitAlertKindEmail)
	state.Click(hitAlertSave)
	if state.modal != modalAlertChannel || state.alertForm.dialogError != state.messages.Tools.NotifyErrEndpoint {
		t.Fatalf("modal %d, error %q", state.modal, state.alertForm.dialogError)
	}
	if state.alertChannels[0].Kind != notify.Webhook {
		t.Fatalf("the refused save changed the kind: %+v", state.alertChannels[0])
	}
}

func TestPushChannelTokensStayOutOfBackupsAndOtherDevices(t *testing.T) {
	if !excludedFromBackup(alertChannelSecretName(1)) {
		t.Fatal("a push channel token would be uploaded with a backup")
	}
}

func TestDeletingAPushChannelForgetsItsToken(t *testing.T) {
	_, options := newWorld(t)
	state := newTestState(t, options)
	addAlertChannel(t, state, "Ops", notify.Webhook, "https://hooks.example.com/secret")
	id := state.alertChannels[0].ID
	state.Click(hitAlertEditList.At(0))
	state.Click(hitAlertDelete)
	if state.modal != modalForm {
		t.Fatalf("delete did not ask: modal %d", state.modal)
	}
	state.Click(hitFormSubmit)
	if state.modal != modalNone || len(state.alertChannels) != 0 {
		t.Fatalf("modal %d, channels %+v", state.modal, state.alertChannels)
	}
	if _, found, _ := state.secrets.vault.Get(alertChannelSecretName(id)); found {
		t.Fatal("the deleted channel's token is still in the vault")
	}
}
