"""A modal nudge for a pending PTES phase move. The status bar already
carries a passive text indicator (StatusBar.phase_proposal); this is the
same proposal surfaced as something that asks for a decision instead of
sitting in a line of text the operator has to notice on their own."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class PhaseApprovalModal(ModalScreen[bool]):
    """Enter/"approve" commits the move; escape/"not now" leaves the
    proposal pending — same either-way-is-fine semantics as typing
    ``/phase <name>`` yourself, just with a visible prompt instead of a
    line in the status bar."""

    BINDINGS = [
        Binding("escape", "dismiss_modal", "not now", show=False),
        Binding("enter", "approve", "approve", show=False),
    ]

    def __init__(self, current: str, proposed: str) -> None:
        super().__init__()
        self.current = current
        self.proposed = proposed

    def compose(self) -> ComposeResult:
        with Vertical(id="phase-approval-frame"):
            yield Static(
                f"move from {self.current} to {self.proposed}?",
                id="phase-approval-title",
                classes="modal-title",
            )
            yield Static(
                f"the engagement looks ready for {self.proposed}. Approve "
                f"to run /phase {self.proposed}, or dismiss to stay in "
                f"{self.current} — the proposal stays pending either way.",
                id="phase-approval-body",
            )
            with Horizontal(id="phase-approval-buttons"):
                yield Button("approve", id="phase-approval-approve", variant="success")
                yield Button("not now", id="phase-approval-not-now")
            yield Static("enter approve · esc not now", classes="modal-hint")

    def on_mount(self) -> None:
        self.query_one("#phase-approval-approve", Button).focus()

    def on_button_pressed(self, message: Button.Pressed) -> None:
        if message.button.id == "phase-approval-approve":
            self.action_approve()
        else:
            self.action_dismiss_modal()

    def action_approve(self) -> None:
        self.dismiss(True)

    def action_dismiss_modal(self) -> None:
        self.dismiss(False)
