//go:build gui

// Command gui is the desktop control panel for Clavis (Fyne).
//
// It lets the user choose the sharing mode applied to new documents
// (proxy "гибридный" / "Прокси" or end-to-end "сквозной" / "Сквозное")
// and shows a modal dialog when somebody requests end-to-end access to
// their document, with an explicit decision: grant the decryption key or
// refuse.
//
// The flow logic lives in internal/gui (toolkit-independent, tested with
// interface doubles); this file only adapts it to Fyne widgets.
//
// Cryptographic operations are performed by the agent (which holds the
// identity); the GUI only talks to its localhost API.
package main

import (
	"flag"
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/clavis/clavis/internal/agentapi"
	"github.com/clavis/clavis/internal/crypto"
	"github.com/clavis/clavis/internal/gui"
	"github.com/clavis/clavis/internal/mode"
)

func main() {
	uiAddr := flag.String("ui", "http://127.0.0.1:8902", "agent localhost API base URL")
	flag.Parse()

	a := app.New()
	w := a.NewWindow("Clavis")

	mgr, err := mode.Open("")
	if err != nil {
		dialog.ShowError(err, w)
	}

	label := widget.NewLabel("Режим шифрования для новых документов:")
	radio := widget.NewRadioGroup([]string{mode.ModeProxyName, mode.ModeE2EName}, func(value string) {
		if m, ok := mode.Parse(value); ok {
			_ = mgr.Set(m)
		}
	})
	radio.SetSelected(modeName(mgr.Get()))
	radio.Horizontal = true

	check := widget.NewButton("Проверить сквозные запросы", func() {
		_, _ = gui.CheckPendingRequests(agentapi.NewClient(*uiAddr), fyneFlow{w: w})
	})

	content := container.NewVBox(
		label,
		radio,
		widget.NewSeparator(),
		check,
	)
	w.SetContent(content)
	w.Resize(fyne.NewSize(460, 220))

	// Poll the agent's localhost API for notifications (e.g. a document
	// could not be opened because its key is missing or the key servers
	// are unreachable) and surface them as system notifications.
	go pollNotifications(a, *uiAddr)

	w.ShowAndRun()
}

func modeName(m crypto.Mode) string {
	s, ok := mode.String(m)
	if !ok {
		return mode.ModeProxyName
	}
	return s
}

// fyneFlow adapts the toolkit-independent approval flow to Fyne dialog
// widgets (see internal/gui).
type fyneFlow struct {
	w fyne.Window
}

// ConfirmApproval implements gui.FlowEvents.
func (f fyneFlow) ConfirmApproval(peerAgent string, onDecision func(bool)) {
	message := fmt.Sprintf(
		"Пользователь %q хочет открыть документ, зашифрованный вами сквозным шифрованием.\n\nДать ключ для расшифровки?",
		peerAgent,
	)
	dialog.ShowConfirm("Доступ к документу", message, onDecision, f.w)
}

// ShowInfo implements gui.FlowEvents.
func (f fyneFlow) ShowInfo(message string) {
	dialog.ShowInformation("Clavis", message, f.w)
}

// ShowError implements gui.FlowEvents.
func (f fyneFlow) ShowError(err error) {
	dialog.ShowError(err, f.w)
}

// fyneNotifier adapts the notification presenter to Fyne system
// notifications (see internal/gui.FetchNewNotifications).
type fyneNotifier struct {
	a fyne.App
}

// ShowNotification implements gui.NotifyPresenter.
func (f fyneNotifier) ShowNotification(title, content string) {
	f.a.SendNotification(&fyne.Notification{Title: title, Content: content})
}

// pollNotifications fetches new notifications from the agent every few
// seconds and shows each of them as a system notification. The last seen
// id (kept in the flow) prevents duplicates.
func pollNotifications(a fyne.App, base string) {
	const pollInterval = 3 * time.Second
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	client := agentapi.NewClient(base)
	presenter := fyneNotifier{a: a}
	var lastID int64
	for range ticker.C {
		// Errors (agent not running yet) are ignored: retry next tick.
		lastID, _, _ = gui.FetchNewNotifications(client, presenter, lastID)
	}
}
