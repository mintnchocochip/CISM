"""The memory view: a modal overlay over the transcript. Rows are
colour-graded by tier and sortable by any column. The footer renders the
salience equation with the highlighted row's term values substituted."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import DataTable, Static

from ..events import MemoryRow, SalienceTerms

TIER_CLASS = {"T1": "mem--t1", "T2": "mem--t2", "T3": "mem--t3"}

COLUMNS: tuple[tuple[str, str], ...] = (
    ("tier", "tier"),
    ("phase", "phase_tag"),
    ("salience", "salience"),
    ("age", "age_s"),
    ("decayed", "decayed"),
    ("snippet", "snippet"),
)


class MemoryTable(DataTable):
    """A DataTable that knows how to colour a cell by memory tier."""

    COMPONENT_CLASSES = DataTable.COMPONENT_CLASSES | {
        "mem--t1",
        "mem--t2",
        "mem--t3",
    }

    def tier_text(self, value: str, tier: str) -> Text:
        return Text(value, style=self.get_component_rich_style(TIER_CLASS[tier]))


class MemoryModal(ModalScreen[None]):
    """Escape closes. Number keys sort by column."""

    BINDINGS = [
        Binding("escape", "dismiss_modal", "close", show=False),
        Binding("ctrl+m", "dismiss_modal", "close", show=False, priority=True),
        Binding("1", "sort(0)", "sort tier", show=False),
        Binding("2", "sort(1)", "sort phase", show=False),
        Binding("3", "sort(2)", "sort salience", show=False),
        Binding("4", "sort(3)", "sort age", show=False),
        Binding("5", "sort(4)", "sort decayed", show=False),
        Binding("6", "sort(5)", "sort snippet", show=False),
    ]

    def __init__(
        self, rows: tuple[MemoryRow, ...], terms: SalienceTerms | None
    ) -> None:
        super().__init__()
        self.rows = rows
        self.terms = terms
        self._sort_index = 4
        self._descending = True

    def compose(self) -> ComposeResult:
        with Vertical(id="memory-frame"):
            yield Static(self._title(), classes="modal-title")
            yield MemoryTable(id="memory-table", cursor_type="row", zebra_stripes=False)
            yield Static(self._equation(None), id="memory-equation",
                         classes="modal-footer")
            yield Static(
                "1-6 sort column · esc to close",
                classes="modal-hint",
            )

    def _title(self) -> str:
        counts: dict[str, int] = {}
        for row in self.rows:
            counts[row.tier] = counts.get(row.tier, 0) + 1
        breakdown = "  ".join(f"{tier}:{counts.get(tier, 0)}" for tier in ("T1", "T2", "T3"))
        return f"memory — {len(self.rows)} items   {breakdown}"

    def on_mount(self) -> None:
        table = self.query_one(MemoryTable)
        for index, (label, _) in enumerate(COLUMNS, start=1):
            table.add_column(f"{index} {label}", key=label)
        self._fill()
        table.focus()

    # -- rows --------------------------------------------------------------

    def _decayed(self, row: MemoryRow) -> float:
        return self.terms.score(row) if self.terms else row.salience

    def _sorted_rows(self) -> list[MemoryRow]:
        keys = (
            lambda r: ("T1", "T2", "T3").index(r.tier),
            lambda r: r.phase_tag,
            lambda r: r.salience,
            lambda r: r.age_s,
            self._decayed,
            lambda r: r.snippet,
        )
        return sorted(self.rows, key=keys[self._sort_index], reverse=self._descending)

    def _fill(self) -> None:
        table = self.query_one(MemoryTable)
        table.clear()
        for row in self._sorted_rows():
            table.add_row(
                table.tier_text(row.tier, row.tier),
                table.tier_text(row.phase_tag, row.tier),
                table.tier_text(f"{row.salience:.2f}", row.tier),
                table.tier_text(f"{row.age_s:.0f}s", row.tier),
                table.tier_text(f"{self._decayed(row):.3f}", row.tier),
                table.tier_text(row.snippet, row.tier),
                key=row.id,
            )
        if self.rows:
            self._update_equation(self._sorted_rows()[0])

    # -- the visible equation ---------------------------------------------

    def _equation(self, row: MemoryRow | None) -> str:
        if self.terms is None:
            return "salience model unavailable"
        return self.terms.equation(row)

    def _update_equation(self, row: MemoryRow | None) -> None:
        self.query_one("#memory-equation", Static).update(self._equation(row))

    def on_data_table_row_highlighted(
        self, message: DataTable.RowHighlighted
    ) -> None:
        ordered = self._sorted_rows()
        if 0 <= message.cursor_row < len(ordered):
            self._update_equation(ordered[message.cursor_row])

    # -- actions -----------------------------------------------------------

    def action_sort(self, index: int) -> None:
        if index == self._sort_index:
            self._descending = not self._descending
        else:
            self._sort_index = index
            self._descending = index in (2, 3, 4)
        self._fill()

    def action_dismiss_modal(self) -> None:
        self.dismiss(None)
