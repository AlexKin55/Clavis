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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
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
	"github.com/clavis/clavis/internal/notify"
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

type notification struct {
	ID   int64       `json:"id"`
	Kind notify.Kind `json:"kind"`
	Text string      `json:"text"`
	Time int64       `json:"time"`
}

// pollNotifications fetches new notifications from the agent every few
// seconds and shows each of them as a system notification. The last seen
// id prevents duplicates.
func pollNotifications(a fyne.App, base string) {
	const pollInterval = 3 * time.Second
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var lastID int64
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/notifications", nil)
		if err != nil {
			cancel()
			continue
		}
		resp, err := http.DefaultClient.Do(req)
		cancel()
		if err != nil {
			continue // agent is not running (yet) — retry on the next tick
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			continue
		}

		var out struct {
			Notifications []notification `json:"notifications"`
		}
		if json.Unmarshal(body, &out) != nil {
			continue
		}
		for _, n := range out.Notifications {
			if n.ID <= lastID {
				continue
			}
			lastID = n.ID
			a.SendNotification(&fyne.Notification{
				Title:   notificationTitle(n.Kind),
				Content: n.Text,
			})
		}
	}
}

// notificationTitle picks a concise title for the notification kind.
func notificationTitle(k notify.Kind) string {
	switch k {
	case notify.KindOffline:
		return "Clavis: нет доступа к серверам ключей"
	case notify.KindKeyMissing:
		return "Clavis: не найден ключ для документа"
	default:
		return "Clavis"
	}
}
