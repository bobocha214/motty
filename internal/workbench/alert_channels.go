package workbench

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/vivaui/viva/components"
	"github.com/vivaui/viva/flex"
	"github.com/vivaui/viva/text"
	"github.com/vivaui/viva/ui"
	"motty/internal/notify"
	"motty/internal/vault"
)

// Push channels are where monitoring alerts will be delivered. The endpoint
// carries the service's token, so it lives in the saved-passwords vault; the
// state file keeps only the name and kind. A channel is device-local: another
// computer has its own tokens and must not overwrite them.

var (
	hitAlertAdd         = tree.ID(settingsHits, "alert-add")
	hitAlertKindWebhook = tree.ID(settingsHits, "alert-kind-webhook")
	hitAlertKindFeishu  = tree.ID(settingsHits, "alert-kind-feishu")
	hitAlertKindDing    = tree.ID(settingsHits, "alert-kind-dingtalk")
	hitAlertKindWeCom   = tree.ID(settingsHits, "alert-kind-wecom")
	hitAlertKindEmail   = tree.ID(settingsHits, "alert-kind-email")
	hitAlertName        = tree.ID(settingsHits, "alert-name")
	hitAlertEndpoint    = tree.ID(settingsHits, "alert-endpoint")
	hitAlertSecret      = tree.ID(settingsHits, "alert-secret")
	hitAlertEmailHost   = tree.ID(settingsHits, "alert-email-host")
	hitAlertEmailUser   = tree.ID(settingsHits, "alert-email-user")
	hitAlertEmailFrom   = tree.ID(settingsHits, "alert-email-from")
	hitAlertEmailTo     = tree.ID(settingsHits, "alert-email-to")
	hitAlertTest        = tree.ID(settingsHits, "alert-test")
	hitAlertSave        = tree.ID(settingsHits, "alert-save")
	hitAlertDelete      = tree.ID(settingsHits, "alert-delete")
	hitAlertCancel      = tree.ID(settingsHits, "alert-cancel")
	hitAlertClose       = tree.ID(settingsHits, "alert-close")
	hitAlertDismiss     = tree.ID(settingsHits, "alert-dismiss")
	hitAlertEditList    = tree.Sub(settingsHits, tree.Name("alert-edit"))
	hitAlertTestList    = tree.Sub(settingsHits, tree.Name("alert-test-row"))
)

const (
	maxAlertChannels    = 50
	maxAlertChannelName = 80
	maxAlertSecret      = 256
	alertTestTimeout    = 15 * time.Second
)

type alertChannel struct {
	ID   uint32
	Name string
	Kind notify.Kind
	// description is the settings row's second line, rebuilt when the channel
	// or the language changes so painting never formats.
	description string
}

type savedAlertChannel struct {
	ID   uint32 `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type alertChannelForm struct {
	editing     int // -1 adds one
	kind        notify.Kind
	name        text.Editor
	endpoint    text.Editor // shared by Webhook/Feishu/DingTalk/WeCom; Email stores JSON in vault slot, not edited directly
	secret      text.Editor // Feishu/DingTalk signing secret, or Email SMTP password
	emailHost   text.Editor // Email-specific: "host:port"
	emailUser   text.Editor // Email-specific: SMTP username
	emailFrom   text.Editor // Email-specific: from address
	emailTo     text.Editor // Email-specific: comma-separated recipients
	dialogError string
	testText    string
	testOK      bool
	testing     bool
	// serial identifies the test whose answer may still be applied.
	serial uint64
}

func alertChannelSecretName(id uint32) string {
	return fmt.Sprintf("alert-channel:%d", id)
}

func alertChannelSigningSecretName(id uint32) string {
	return fmt.Sprintf("alert-channel:%d:secret", id)
}

func (state *State) alertKindName(kind notify.Kind) string {
	m := state.messages.Tools
	switch kind {
	case notify.Feishu:
		return m.NotifyKindFeishu
	case notify.DingTalk:
		return m.NotifyKindDingTalk
	case notify.WeCom:
		return m.NotifyKindWeCom
	case notify.Email:
		return m.NotifyKindEmail
	}
	return m.NotifyKindWebhook
}

func (state *State) refreshAlertChannelDescriptions() {
	for index := range state.alertChannels {
		state.alertChannels[index].description = state.alertKindName(state.alertChannels[index].Kind)
	}
}

func (state *State) savedAlertChannels() []savedAlertChannel {
	if len(state.alertChannels) == 0 {
		return nil
	}
	list := make([]savedAlertChannel, 0, len(state.alertChannels))
	for _, channel := range state.alertChannels {
		list = append(list, savedAlertChannel{ID: channel.ID, Name: channel.Name, Kind: channel.Kind.String()})
	}
	return list
}

func (state *State) restoreAlertChannels(saved []savedAlertChannel) {
	state.alertChannels = state.alertChannels[:0]
	var next uint32
	seen := make(map[uint32]bool, len(saved))
	for _, entry := range saved {
		name := strings.TrimSpace(entry.Name)
		if entry.ID == 0 || name == "" || len([]rune(name)) > maxAlertChannelName || seen[entry.ID] {
			continue
		}
		kind, ok := notify.KindFromString(entry.Kind)
		if !ok {
			continue
		}
		seen[entry.ID] = true
		state.alertChannels = append(state.alertChannels, alertChannel{ID: entry.ID, Name: name, Kind: kind})
		if entry.ID >= next {
			next = entry.ID + 1
		}
		if len(state.alertChannels) == maxAlertChannels {
			break
		}
	}
	state.nextAlertChannelID = max(state.nextAlertChannelID, next)
	state.refreshAlertChannelDescriptions()
}

func (state *State) alertChannelByID(id uint32) (*alertChannel, bool) {
	for index := range state.alertChannels {
		if state.alertChannels[index].ID == id {
			return &state.alertChannels[index], true
		}
	}
	return nil, false
}

// alertChannelEndpoint reads the token-bearing address from the vault. A locked
// or missing vault has no endpoint to send to.
func (state *State) alertChannelEndpoint(id uint32) (string, bool) {
	opened := state.secrets.vault
	if opened == nil || opened.NeedsConversion() {
		return "", false
	}
	value, found, err := opened.Get(alertChannelSecretName(id))
	if err != nil || !found {
		return "", false
	}
	return value, true
}

// alertChannelSigningSecret reads the optional Feishu/DingTalk signing key. A
// missing entry is not an error: signing is optional.
func (state *State) alertChannelSigningSecret(id uint32) string {
	opened := state.secrets.vault
	if opened == nil || opened.NeedsConversion() {
		return ""
	}
	value, found, err := opened.Get(alertChannelSigningSecretName(id))
	if err != nil || !found {
		return ""
	}
	return value
}

func (state *State) openAlertChannelForm(editing int) {
	form := &state.alertForm
	form.editing, form.kind = editing, notify.Webhook
	form.name, form.endpoint, form.secret = text.Editor{}, text.Editor{}, text.Editor{}
	form.emailHost, form.emailUser, form.emailFrom, form.emailTo = text.Editor{}, text.Editor{}, text.Editor{}, text.Editor{}
	form.dialogError, form.testText, form.testOK, form.testing = "", "", false, false
	form.serial++
	if editing >= 0 && editing < len(state.alertChannels) {
		channel := &state.alertChannels[editing]
		form.kind = channel.Kind
		form.name.Insert(channel.Name)
		if channel.Kind == notify.Email {
			// Load saved JSON config into dedicated Email fields.
			if raw, ok := state.alertChannelEndpoint(channel.ID); ok {
				if cfg, err := notify.ParseEmailConfig(raw); err == nil {
					host := cfg.Host
					if cfg.Port > 0 {
						host = fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
					}
					form.emailHost.Insert(host)
					form.emailUser.Insert(cfg.Username)
					form.emailFrom.Insert(cfg.From)
					form.emailTo.Insert(strings.Join(cfg.To, ", "))
				}
			}
		}
	}
	state.modal = modalAlertChannel
}

func (state *State) clickAlertChannels(id ui.ID) bool {
	switch {
	case id == hitAlertAdd:
		state.openAlertChannelForm(-1)
	case id.Scope() == hitAlertEditList:
		if index := item(id); index >= 0 && index < len(state.alertChannels) {
			state.openAlertChannelForm(index)
		}
	case id.Scope() == hitAlertTestList:
		if index := item(id); index >= 0 && index < len(state.alertChannels) {
			state.testAlertChannelByID(state.alertChannels[index].ID)
		}
	default:
		return false
	}
	return true
}

func (state *State) clickAlertChannel(id ui.ID) {
	form := &state.alertForm
	switch id {
	case hitAlertKindWebhook:
		form.kind = notify.Webhook
	case hitAlertKindFeishu:
		form.kind = notify.Feishu
	case hitAlertKindDing:
		form.kind = notify.DingTalk
	case hitAlertKindWeCom:
		form.kind = notify.WeCom
	case hitAlertKindEmail:
		form.kind = notify.Email
	case hitAlertTest:
		state.testAlertChannelForm()
	case hitAlertSave:
		state.submitAlertChannel()
	case hitAlertDelete:
		state.confirmDeleteAlertChannel()
	case hitAlertCancel, hitAlertClose, hitAlertDismiss:
		state.closeModal()
	}
}

// formChannel is what the dialog currently describes, or the saved endpoint
// when the field is left empty while editing.
func (state *State) formChannel() (notify.Channel, bool, string) {
	form := &state.alertForm

	var endpoint string
	var secret string

	if form.kind == notify.Email {
		// Email packs its dedicated fields into the endpoint slot as JSON.
		endpoint, secret = state.emailFormConfig()
		if endpoint == "" && form.editing >= 0 && form.editing < len(state.alertChannels) {
			// Reuse saved JSON if all Email fields are empty (keeping config).
			if form.kind != state.alertChannels[form.editing].Kind {
				return notify.Channel{}, false, state.messages.Tools.NotifyErrEndpoint
			}
			if opened := state.secrets.vault; opened != nil && opened.NeedsConversion() {
				return notify.Channel{}, false, state.messages.Tools.NotifyErrLocked
			}
			saved, ok := state.alertChannelEndpoint(state.alertChannels[form.editing].ID)
			if !ok {
				return notify.Channel{}, false, state.messages.Tools.NotifyErrEndpoint
			}
			endpoint = saved
		}
		if secret == "" && form.editing >= 0 && form.editing < len(state.alertChannels) {
			// Reuse saved SMTP password.
			if form.kind == state.alertChannels[form.editing].Kind {
				secret = state.alertChannelSigningSecret(state.alertChannels[form.editing].ID)
			}
		}
	} else {
		endpoint = strings.TrimSpace(form.endpoint.String())
		if endpoint == "" && form.editing >= 0 && form.editing < len(state.alertChannels) {
			if form.kind != state.alertChannels[form.editing].Kind {
				return notify.Channel{}, false, state.messages.Tools.NotifyErrEndpoint
			}
			if opened := state.secrets.vault; opened != nil && opened.NeedsConversion() {
				return notify.Channel{}, false, state.messages.Tools.NotifyErrLocked
			}
			saved, ok := state.alertChannelEndpoint(state.alertChannels[form.editing].ID)
			if !ok {
				return notify.Channel{}, false, state.messages.Tools.NotifyErrEndpoint
			}
			endpoint = saved
		}
		secret = strings.TrimSpace(form.secret.String())
		if form.kind.Signed() && secret == "" && form.editing >= 0 && form.editing < len(state.alertChannels) &&
			form.kind == state.alertChannels[form.editing].Kind {
			secret = state.alertChannelSigningSecret(state.alertChannels[form.editing].ID)
		}
		if !form.kind.Signed() {
			secret = ""
		}
	}

	if len(secret) > maxAlertSecret {
		return notify.Channel{}, false, state.messages.Tools.NotifyErrSecret
	}
	channel := notify.Channel{Kind: form.kind, Endpoint: endpoint, Secret: secret}
	if err := channel.Validate(); err != nil {
		return notify.Channel{}, false, state.messages.Tools.NotifyErrEndpoint
	}
	return channel, true, ""
}

// emailFormConfig reads the four Email inputs and returns (jsonConfig, password).
// An empty jsonConfig means all Email fields are blank — caller should preserve
// the saved one.
func (state *State) emailFormConfig() (string, string) {
	form := &state.alertForm
	hostPort := strings.TrimSpace(form.emailHost.String())
	user := strings.TrimSpace(form.emailUser.String())
	from := strings.TrimSpace(form.emailFrom.String())
	toRaw := strings.TrimSpace(form.emailTo.String())
	secret := strings.TrimSpace(form.secret.String())

	if hostPort == "" && user == "" && from == "" && toRaw == "" {
		return "", secret
	}

	host := hostPort
	port := 0
	if idx := strings.LastIndex(hostPort, ":"); idx > 0 {
		host = hostPort[:idx]
		if p, err := strconv.Atoi(hostPort[idx+1:]); err == nil {
			port = p
		}
	}
	var toList []string
	for _, addr := range strings.Split(toRaw, ",") {
		if trimmed := strings.TrimSpace(addr); trimmed != "" {
			toList = append(toList, trimmed)
		}
	}
	cfg := notify.EmailConfig{Host: host, Port: port, Username: user, From: from, To: toList}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return "", secret
	}
	return string(raw), secret
}

func (state *State) testAlertChannelForm() {
	form := &state.alertForm
	channel, ok, message := state.formChannel()
	if !ok {
		form.dialogError, form.testText, form.testOK = message, "", false
		return
	}
	state.sendAlertTest(channel, func(text string, ok bool) {
		if state.modal != modalAlertChannel {
			return
		}
		form := &state.alertForm
		form.testing, form.testText, form.testOK = false, text, ok
		if ok {
			form.dialogError = ""
		}
	}, &form.testing, &form.serial)
}

func (state *State) testAlertChannelByID(id uint32) {
	channel, found := state.alertChannelByID(id)
	if !found {
		return
	}
	endpoint, ok := state.alertChannelEndpoint(id)
	if !ok {
		state.status = state.messages.Tools.NotifyErrLocked
		return
	}
	state.sendAlertTest(notify.Channel{Kind: channel.Kind, Endpoint: endpoint, Secret: state.alertChannelSigningSecret(id)}, func(text string, ok bool) {
		state.status = text
	}, nil, nil)
}

// sendAlertTest runs the request off the window thread and posts the outcome
// back. The optional fields belong to the dialog, which may have been closed or
// replaced by the time the answer arrives.
func (state *State) sendAlertTest(channel notify.Channel, done func(string, bool), testing *bool, serial *uint64) {
	if testing != nil {
		*testing = true
	}
	if serial != nil {
		*serial = *serial + 1
	}
	generation := uint64(0)
	if serial != nil {
		generation = *serial
	}
	event := notify.Event{
		Kind: "test", Title: state.messages.Tools.NotifyTestTitle,
		Body: state.messages.Tools.NotifyTestBody, Time: time.Now(),
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), alertTestTimeout)
		defer cancel()
		err := notify.Send(ctx, nil, channel, event)
		text := state.messages.Tools.NotifyTestSent
		ok := true
		if err != nil {
			text, ok = fmt.Sprintf(state.messages.Tools.NotifyTestFailedFmt, err.Error()), false
		}
		state.aiPost(func(state *State) {
			if serial != nil && *serial != generation {
				return
			}
			done(text, ok)
		})
	}()
}

func (state *State) submitAlertChannel() {
	form, m := &state.alertForm, state.messages.Tools
	name := strings.TrimSpace(form.name.String())
	switch {
	case name == "" || len([]rune(name)) > maxAlertChannelName:
		form.dialogError = m.NotifyErrName
		return
	}
	channel, ok, message := state.formChannel()
	if !ok {
		form.dialogError = message
		return
	}
	opened := state.secrets.vault
	if opened == nil {
		form.dialogError = m.NotifyErrNoVault
		return
	}
	if opened.NeedsConversion() {
		form.dialogError = m.NotifyErrLocked
		return
	}
	editing := form.editing >= 0 && form.editing < len(state.alertChannels)
	if !editing && len(state.alertChannels) >= maxAlertChannels {
		form.dialogError = m.NotifyErrLimit
		return
	}
	id := state.nextAlertChannelID
	if editing {
		id = state.alertChannels[form.editing].ID
	}
	changes := []vault.Change{{Name: alertChannelSecretName(id), Value: channel.Endpoint}}
	if form.kind.Signed() && channel.Secret != "" {
		changes = append(changes, vault.Change{Name: alertChannelSigningSecretName(id), Value: channel.Secret})
	} else {
		changes = append(changes, vault.Change{Name: alertChannelSigningSecretName(id), Delete: true})
	}
	if err := opened.Apply(changes); err != nil {
		if errors.Is(err, vault.ErrNeedsConversion) {
			form.dialogError = m.NotifyErrLocked
		} else {
			form.dialogError = fmt.Sprintf(state.messages.VaultSaveFailedFmt, state.vaultErrorText(err))
		}
		return
	}
	saved := alertChannel{ID: id, Name: name, Kind: form.kind}
	if editing {
		state.alertChannels[form.editing] = saved
	} else {
		state.alertChannels = append(state.alertChannels, saved)
		state.nextAlertChannelID = id + 1
	}
	state.refreshAlertChannelDescriptions()
	state.closeModal()
	state.save()
}

func (state *State) confirmDeleteAlertChannel() {
	form := &state.alertForm
	if form.editing < 0 || form.editing >= len(state.alertChannels) {
		return
	}
	channel := state.alertChannels[form.editing]
	m := state.messages.Tools
	index := form.editing
	state.openForm(formDialog{
		title: m.NotifyConfirmDeleteTitle, description: fmt.Sprintf(m.NotifyConfirmDeleteFmt, channel.Name),
		submit: m.NotifyDelete, danger: true,
		run: func(state *State, _ *formDialog) string {
			state.removeAlertChannel(index)
			return ""
		},
	})
}

func (state *State) removeAlertChannel(index int) {
	if index < 0 || index >= len(state.alertChannels) {
		return
	}
	channel := state.alertChannels[index]
	state.alertChannels = append(state.alertChannels[:index], state.alertChannels[index+1:]...)
	if opened := state.secrets.vault; opened != nil && !opened.NeedsConversion() {
		_ = opened.Apply([]vault.Change{
			{Name: alertChannelSecretName(channel.ID), Delete: true},
			{Name: alertChannelSigningSecretName(channel.ID), Delete: true},
		})
	}
	state.refreshAlertChannelDescriptions()
	state.save()
}

func (state *State) paintNotificationSettings(page *settingsPage) {
	m := state.messages.Tools
	page.groups(func() {
		page.group(m.NotifyChannels, func() {
			if len(state.alertChannels) == 0 {
				page.actionRow(m.NotifyEmpty, m.NotifyEmptyHint, false,
					components.ButtonAction{ID: hitAlertAdd, Label: m.NotifyAdd, Variant: components.ButtonDefault})
				return
			}
			for index := range state.alertChannels {
				channel := &state.alertChannels[index]
				page.actionRow(channel.Name, channel.description, false,
					components.ButtonAction{ID: hitAlertEditList.At(index), Label: m.NotifyEdit, Variant: components.ButtonOutline},
					components.ButtonAction{ID: hitAlertTestList.At(index), Label: m.NotifyTest, Variant: components.ButtonOutline})
			}
			page.actionRow(m.NotifyAdd, "", false,
				components.ButtonAction{ID: hitAlertAdd, Label: m.NotifyAdd, Variant: components.ButtonDefault})
		})
	})
}

func (state *State) paintAlertChannelDialog(canvas *ui.Canvas, viewport ui.Rect) {
	m, theme, pal := state.messages.Tools, state.Theme(), state.pal
	form := &state.alertForm
	title := m.NotifyAddTitle
	if form.editing >= 0 {
		title = m.NotifyEditTitle
	}
	signed := form.kind.Signed()
	isEmail := form.kind == notify.Email

	// 固定 slots 布局
	bodyHeight := float32(34 + 14 + 62) // kind row + name
	if isEmail {
		bodyHeight += 4 * 62 // host/user/from/to
		bodyHeight += 88 // password
	} else {
		bodyHeight += 88 // endpoint
		if signed {
			bodyHeight += 88 // signing secret
		}
	}
	if form.testText != "" {
		bodyHeight += 24
	}

	dialog := components.BeginDialog(canvas, theme, viewport, components.DialogOptions{
		Layer: dialogLayer, Scope: dialogScope,
		DismissID: hitAlertDismiss, CloseID: hitAlertClose, InitialFocusID: hitAlertName,
		ContentSize: ui.Size{Width: 720}, FitBody: true, BodyHeight: withError(bodyHeight, form.dialogError),
	})
	layout := dialog.Begin(title, m.NotifyDialogDescription)

	var kind, nameSlot, endpointSlot, secretSlot, testSlot, emailHostSlot, emailUserSlot, emailFromSlot, emailToSlot flex.Box
	f := state.settingsRow.Begin(canvas, theme, layout.Body)
	f.Column().Fill().PadSides(2, 4, 0, 4).Children(func() {
		kind = f.Slot().Height(34).MarginSides(0, 0, 14, 0)
		nameSlot = f.Slot().Height(62).MarginSides(0, 0, 4, 0)
		if isEmail {
			emailHostSlot = f.Slot().Height(62).MarginSides(0, 0, 4, 0)
			emailUserSlot = f.Slot().Height(62).MarginSides(0, 0, 4, 0)
			emailFromSlot = f.Slot().Height(62).MarginSides(0, 0, 4, 0)
			emailToSlot = f.Slot().Height(62).MarginSides(0, 0, 4, 0)
			secretSlot = f.Slot().Height(88).MarginSides(0, 0, 4, 0)
		} else {
			endpointSlot = f.Slot().Height(88).MarginSides(0, 0, 4, 0)
			if signed {
				secretSlot = f.Slot().Height(88).MarginSides(0, 0, 4, 0)
			}
		}
		if form.testText != "" {
			testSlot = f.Slot().Height(24).MarginSides(0, 0, 4, 0)
		}
		state.problemLine(f, form.dialogError)
	})
	f.End()

	// 选中类型高亮
	selected := hitAlertKindWebhook
	switch form.kind {
	case notify.Feishu:
		selected = hitAlertKindFeishu
	case notify.DingTalk:
		selected = hitAlertKindDing
	case notify.WeCom:
		selected = hitAlertKindWeCom
	case notify.Email:
		selected = hitAlertKindEmail
	}
	options := [...]components.SegmentOption{
		{ID: hitAlertKindWebhook, Label: m.NotifyKindWebhook},
		{ID: hitAlertKindFeishu, Label: m.NotifyKindFeishu},
		{ID: hitAlertKindDing, Label: m.NotifyKindDingTalk},
		{ID: hitAlertKindWeCom, Label: m.NotifyKindWeCom},
		{ID: hitAlertKindEmail, Label: m.NotifyKindEmail},
	}
	components.BeginSegmentedControl(canvas, theme, kind.Rect(), options[:], selected).Paint()

	// 表单字段渲染
	for _, field := range [...]struct {
		id          ui.ID
		label       string
		description string
		editor      *text.Editor
		slot        flex.Box
		secure      bool
		placeholder string
	}{
		{hitAlertName, m.NotifyName, "", &form.name, nameSlot, false, m.NotifyNamePlaceholder},
	} {
		content := components.BeginField(canvas, theme, field.slot.Rect()).Paint(field.label, field.description, "")
		value := field.editor.String()
		focused := canvas.Focused() == field.id
		state.paintSecretInput(canvas, content, components.InputSnapshot{
			ID: field.id, Label: field.label, Value: value, Placeholder: field.placeholder,
			Secure: field.secure, Focused: focused, PlatformEditing: focused && value != "",
		})
	}

	if isEmail {
		// Email 专用字段
		for _, field := range [...]struct {
			id          ui.ID
			label       string
			description string
			editor      *text.Editor
			slot        flex.Box
			secure      bool
			placeholder string
		}{
			{hitAlertEmailHost, m.NotifyEmailHost, "", &form.emailHost, emailHostSlot, false, m.NotifyEmailHostPlaceholder},
			{hitAlertEmailUser, m.NotifyEmailUser, "", &form.emailUser, emailUserSlot, false, m.NotifyEmailUserPlaceholder},
			{hitAlertEmailFrom, m.NotifyEmailFrom, "", &form.emailFrom, emailFromSlot, false, m.NotifyEmailFromPlaceholder},
			{hitAlertEmailTo, m.NotifyEmailTo, "", &form.emailTo, emailToSlot, false, m.NotifyEmailToPlaceholder},
		} {
			content := components.BeginField(canvas, theme, field.slot.Rect()).Paint(field.label, field.description, "")
			value := field.editor.String()
			focused := canvas.Focused() == field.id
			state.paintSecretInput(canvas, content, components.InputSnapshot{
				ID: field.id, Label: field.label, Value: value, Placeholder: field.placeholder,
				Secure: field.secure, Focused: focused, PlatformEditing: focused && value != "",
			})
		}
		// Email password
		content := components.BeginField(canvas, theme, secretSlot.Rect()).Paint(m.NotifyEmailPassword, "", "")
		value := form.secret.String()
		focused := canvas.Focused() == hitAlertSecret
		placeholder := m.NotifyEmailPasswordPlaceholder
		if form.editing >= 0 {
			placeholder = m.NotifyEmailPasswordPlaceholder
		}
		state.paintSecretInput(canvas, content, components.InputSnapshot{
			ID: hitAlertSecret, Label: m.NotifyEmailPassword, Value: value, Placeholder: placeholder,
			Secure: true, Focused: focused, PlatformEditing: focused && value != "",
		})
	} else {
		// 非 Email：endpoint + 可选 secret
		endpointPh := "https://"
		if form.editing >= 0 {
			endpointPh = m.NotifyEndpointKeep
		}
		content := components.BeginField(canvas, theme, endpointSlot.Rect()).Paint(m.NotifyEndpoint, m.NotifyEndpointHint, "")
		value := form.endpoint.String()
		focused := canvas.Focused() == hitAlertEndpoint
		state.paintSecretInput(canvas, content, components.InputSnapshot{
			ID: hitAlertEndpoint, Label: m.NotifyEndpoint, Value: value, Placeholder: endpointPh,
			Secure: false, Focused: focused, PlatformEditing: focused && value != "",
		})
		if signed {
			secretPh := m.NotifySecretPlaceholder
			if form.editing >= 0 {
				secretPh = m.NotifySecretKeep
			}
			content := components.BeginField(canvas, theme, secretSlot.Rect()).Paint(m.NotifySecret, m.NotifySecretHint, "")
			value := form.secret.String()
			focused := canvas.Focused() == hitAlertSecret
			state.paintSecretInput(canvas, content, components.InputSnapshot{
				ID: hitAlertSecret, Label: m.NotifySecret, Value: value, Placeholder: secretPh,
				Secure: true, Focused: focused, PlatformEditing: focused && value != "",
			})
		}
	}

	if form.testText != "" {
		rect := testSlot.Rect()
		color := pal.muted
		if !form.testOK {
			color = pal.danger
		}
		canvas.Label(elide(canvas, form.testText, metrics.FontSizeS, ui.WeightRegular, rect.Width), rect, ui.TextStyle{Size: metrics.FontSizeS, Color: color})
	}

	actions := []components.ButtonAction{}
	if form.editing >= 0 {
		actions = append(actions, components.ButtonAction{ID: hitAlertDelete, Label: m.NotifyDelete, Variant: components.ButtonDestructive})
	}
	actions = append(actions,
		components.ButtonAction{ID: hitAlertCancel, Label: state.messages.Cancel, Variant: components.ButtonSecondary},
		components.ButtonAction{ID: hitAlertTest, Label: m.NotifyTest, Variant: components.ButtonOutline, Disabled: form.testing},
		components.ButtonAction{ID: hitAlertSave, Label: m.NotifySave},
	)
	dialog.Actions(layout, actions...)
	dialog.End()
}
