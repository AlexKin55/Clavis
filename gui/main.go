//go:build gui

// Command gui is the desktop control panel for Clavis (Fyne).
//
// It lets the user choose the sharing mode applied to new documents
// (proxy "гибридный" / "Прокси" or end-to-end "сквозной" / "Сквозное")
// and shows a modal dialog when somebody requests end-to-end access to
// their document, with an explicit decision: grant the decryption key or
// refuse.
//
// Cryptographic operations are performed by the agent (which holds the
// identity); the GUI only talks to its localhost API.
package main

import (
	"bytes"
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

	"github.com/clavis/clavis/internal/crypto"
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
		checkPending(w, *uiAddr)
	})

	content := container.NewVBox(
		label,
		radio,
		widget.NewSeparator(),
		check,
	)
	w.SetContent(content)
	w.Resize(fyne.NewSize(460, 220))
	w.ShowAndRun()
}

func modeName(m crypto.Mode) string {
	s, ok := mode.String(m)
	if !ok {
		return mode.ModeProxyName
	}
	return s
}

func checkPending(w fyne.Window, base string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/e2e/pending", nil)
	if err != nil {
		dialog.ShowError(err, w)
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		dialog.ShowInformation("Clavis", "Агент недоступен: "+err.Error(), w)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		dialog.ShowError(err, w)
		return
	}
	var out struct {
		Pending []pending `json:"pending"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		dialog.ShowError(err, w)
		return
	}
	if len(out.Pending) == 0 {
		dialog.ShowInformation("Clavis", "Нет ожидающих сквозных запросов.", w)
		return
	}

	first := out.Pending[0]
	message := fmt.Sprintf(
		"Пользователь %q хочет открыть документ, зашифрованный вами сквозным шифрованием.\n\nДать ключ для расшифровки?",
		first.PeerAgent,
	)
	dialog.ShowConfirm("Доступ к документу", message,
		func(grant bool) {
			if grant {
				approve(w, base, first.SessionID)
			} else {
				dialog.ShowInformation("Clavis", "Запрос отклонён.", w)
			}
		}, w)
}

func approve(w fyne.Window, base, sessionID string) {
	payload, _ := json.Marshal(map[string]string{"session_id": sessionID})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/e2e/approve", bytes.NewReader(payload))
	if err != nil {
		dialog.ShowError(err, w)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		dialog.ShowError(err, w)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dialog.ShowInformation("Clavis", "Не удалось передать ключ: HTTP "+resp.Status, w)
		return
	}
	dialog.ShowInformation("Clavis", "Ключ доступа передан.", w)
}

type pending struct {
	SessionID string `json:"session_id"`
	PeerAgent string `json:"peer_agent_id"`
}
