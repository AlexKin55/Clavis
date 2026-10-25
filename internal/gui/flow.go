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
// listing pending e2e requests and approving them. The HTTP client in
// internal/agentapi implements it.
type AgentAPI interface {
	PendingE2ESessions(ctx context.Context) ([]agentapi.PendingE2ESession, error)
	ApproveE2ESession(ctx context.Context, sessionID string) error
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
