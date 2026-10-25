// Package gui contains the toolkit-independent flow logic of the desktop
// control panel. The approval and notification primitives are expressed
// as small interfaces (FlowEvents), so the flow can be exercised with
// test doubles — no GUI runtime required. The Fyne frontend (gui/main.go)
// adapts these interfaces to dialog widgets.
package gui

import (
	"context"
	"time"

	"github.com/clavis/clavis/internal/agentapi"
)

const (
	pendingTimeout = 3 * time.Second
	approveTimeout = 5 * time.Second
)

// FlowEvents abstracts the user-interface primitives the approval flow
// needs. Implementations must be a thin adapter over the actual widgets.
type FlowEvents interface {
	// ConfirmApproval asks the user to grant or refuse end-to-end access
	// for the peer. onDecision is invoked with the chosen answer.
	ConfirmApproval(peerAgent string, onDecision func(grant bool))
	// ShowInfo reports an informational outcome (nothing pending,
	// request declined, key handed over).
	ShowInfo(message string)
	// ShowError reports a failed request (agent unreachable, approval
	// rejected by the agent).
	ShowError(err error)
}

// AgentAPI is the slice of the agent's localhost API the flow needs:
// listing pending e2e requests, approving them and reading notifications.
// The HTTP client in internal/agentapi implements it.
type AgentAPI interface {
	PendingE2ESessions(ctx context.Context) ([]agentapi.PendingE2ESession, error)
	ApproveE2ESession(ctx context.Context, sessionID string) error
	Notifications(ctx context.Context) ([]agentapi.Notification, error)
}

// NotifyPresenter shows a single notification to the user (a system
// notification or a dialog), with the title already resolved.
type NotifyPresenter interface {
	ShowNotification(title, content string)
}

// CheckPendingRequests fetches the end-to-end requests awaiting the
// owner and, when at least one exists, shows the approval dialog. The
// user's decision is applied asynchronously by the UI (grant calls the
// agent's approve endpoint). It returns the number of pending sessions.
func CheckPendingRequests(api AgentAPI, ui FlowEvents) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pendingTimeout)
	defer cancel()

	sessions, err := api.PendingE2ESessions(ctx)
	if err != nil {
		ui.ShowError(err)
		return 0, err
	}
	if len(sessions) == 0 {
		ui.ShowInfo("Нет ожидающих сквозных запросов.")
		return 0, nil
	}

	first := sessions[0]
	ui.ConfirmApproval(first.PeerAgent, func(grant bool) {
		if !grant {
			ui.ShowInfo("Запрос отклонён.")
			return
		}
		approveCtx, approveCancel := context.WithTimeout(context.Background(), approveTimeout)
		defer approveCancel()
		if err := api.ApproveE2ESession(approveCtx, first.SessionID); err != nil {
			ui.ShowError(err)
			return
		}
		ui.ShowInfo("Ключ доступа передан.")
	})
	return len(sessions), nil
}

// FetchNewNotifications fetches the agent's recent notifications and
// presents every one newer than lastID once (deduplicated by id). It
// returns the new last seen id and the number of displayed notifications.
// A notification with kind "key_missing" means no key could be found to
// decrypt a document (a possible offline agent); "offline" means the
// key servers were unreachable.
func FetchNewNotifications(api AgentAPI, presenter NotifyPresenter, lastID int64) (int64, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	notes, err := api.Notifications(ctx)
	if err != nil {
		return lastID, 0, err
	}
	shown := 0
	for _, n := range notes {
		if n.ID <= lastID {
			continue
		}
		lastID = n.ID
		presenter.ShowNotification(notificationTitle(n.Kind), n.Text)
		shown++
	}
	return lastID, shown, nil
}

// notificationTitle resolves the user-facing title for a notification
// kind ("key_missing", "offline", else generic).
func notificationTitle(kind string) string {
	switch kind {
	case "key_missing":
		return "Clavis: не найден ключ для документа"
	case "offline":
		return "Clavis: нет доступа к серверам ключей"
	default:
		return "Clavis"
	}
}
