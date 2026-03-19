#!/usr/bin/env python3

from __future__ import annotations

import sys
import math
import subprocess
import argparse
from pathlib import Path

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static
from textual.widget import Widget
from textual.message import Message
from textual.strip import Strip
from textual import events

import pyfsig

from rich.segment import Segment
from rich.style import Style

BYTES_PER_ROW = 16
# Total rendered width of one hex view line:
# "00000000  " + hex bytes + extra mid-gap + "  |" + ascii + "|"
HEX_LINE_WIDTH = 10 + (3 * BYTES_PER_ROW - 1) + 1 + 3 + BYTES_PER_ROW + 1


# ── Magic byte detection ─────────────────────────────────────────────────────────

def detect_file_type(data: bytes | bytearray) -> str:
    matches = pyfsig.find_matches_for_file_header(bytes(data))
    if not matches:
        return ""
    m = matches[0]
    return m.description or m.display_string or m.file_extension


# ── Entropy ─────────────────────────────────────────────────────────────────────

def shannon_entropy(data: bytes | bytearray) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


# ── Entropy bar widget ──────────────────────────────────────────────────────────

class MagicBar(Static):
    DEFAULT_CSS = """
    MagicBar {
        background: $panel;
        color: $foreground-muted;
        height: 1;
        padding: 0 1;
    }
    """

    def __init__(self, file_type: str, **kwargs) -> None:
        label = (
            f"[bright_blue bold]MAGIC BYTES[/]  [bright_black]│[/]  [bold magenta]{file_type}[/]"
            if file_type else
            "[bright_blue bold]MAGIC BYTES[/]  [bright_black]│[/]  [bright_black]unknown[/]"
        )
        super().__init__(label, **kwargs)


class EntropyBar(Static):
    DEFAULT_CSS = """
    EntropyBar {
        background: $background-darken-1;
        color: $foreground-muted;
        height: 1;
        padding: 0 1;
    }
    """

    def update_entropy(self, entropy: float) -> None:
        pct = entropy / 8.0
        self.update(
            f"[bright_blue bold]SHANNON ENTROPY[/]  "
            f"[bold white]{entropy:.4f}[/][bright_black] / 8[/]"
            f"  [bright_black]([/][bold white]{pct * 100:.1f}%[/][bright_black])[/]"
        )


# ── Hex view widget ─────────────────────────────────────────────────────────────

class HexView(Widget):
    """Hex editor pane — owns its own scroll state via view_top."""

    can_focus = True

    class CursorMoved(Message):
        def __init__(self, pos: int, byte_val: int, modified: bool, pane: str) -> None:
            super().__init__()
            self.pos = pos
            self.byte_val = byte_val
            self.modified = modified
            self.pane = pane

    class EntropyUpdate(Message):
        def __init__(self, entropy: float) -> None:
            super().__init__()
            self.entropy = entropy

    class SelectionChanged(Message):
        def __init__(self, sel: tuple[int, int] | None) -> None:
            super().__init__()
            self.sel = sel

    DEFAULT_CSS = """
    HexView {
        background: $background;
        color: $foreground;
    }
    """

    def __init__(self, data: bytearray, **kwargs) -> None:
        super().__init__(**kwargs)
        self.data = data
        self.original = bytearray(data)
        self.cursor_pos: int = 0
        self.edit_pane: str = "hex"
        self.pending_nibble: int | None = None
        self.modified: bool = False
        self.view_top: int = 0          # first visible row index
        self._sel_anchor: int | None = None
        self._sel_end: int | None = None
        self._dragging: bool = False

    def _total_rows(self) -> int:
        return max(1, (len(self.data) + BYTES_PER_ROW - 1) // BYTES_PER_ROW)

    def sel_range(self) -> tuple[int, int] | None:
        """Returns (lo, hi) inclusive byte indices of current selection, or None."""
        if self._sel_anchor is None or self._sel_end is None:
            return None
        return (min(self._sel_anchor, self._sel_end),
                max(self._sel_anchor, self._sel_end))

    def _xy_to_byte_index(self, x: int, y: int) -> int | None:
        """Convert widget-local (x, y) to a byte index, or None if outside data."""
        row = self.view_top + y
        base = row * BYTES_PER_ROW
        # Hex pane — first group bytes 0-7 (x 10..32)
        if 10 <= x <= 32:
            col = (x - 10) // 3
            idx = base + col
            return idx if 0 <= col < BYTES_PER_ROW and idx < len(self.data) else None
        # Hex pane — second group bytes 8-15 (x 35..57, +1 for mid-gap)
        if 35 <= x <= 57:
            col = 8 + (x - 35) // 3
            idx = base + col
            return idx if 0 <= col < BYTES_PER_ROW and idx < len(self.data) else None
        # ASCII pane (x 61..76)
        if 61 <= x < 61 + BYTES_PER_ROW:
            col = x - 61
            idx = base + col
            return idx if idx < len(self.data) else None
        return None

    def render_line(self, y: int) -> Strip:
        row = self.view_top + y
        offset = row * BYTES_PER_ROW

        if offset >= len(self.data):
            return Strip.blank(self.size.width)

        row_bytes = self.data[offset : offset + BYTES_PER_ROW]
        segments: list[Segment] = []
        sel = self.sel_range()

        segments.append(Segment(f"{offset:08x}  ", Style.parse("bright_blue")))

        for i in range(BYTES_PER_ROW):
            byte_pos = offset + i
            if i < len(row_bytes):
                byte = row_bytes[i]
                is_cursor = byte_pos == self.cursor_pos
                is_modified = byte_pos < len(self.original) and byte != self.original[byte_pos]
                is_selected = sel is not None and sel[0] <= byte_pos <= sel[1]

                if is_cursor and self.edit_pane == "hex":
                    style = Style.parse("black on yellow bold")
                elif is_selected:
                    style = Style.parse("black on bright_cyan")
                elif is_modified:
                    style = Style.parse("bright_red")
                else:
                    style = Style.parse("white")

                segments.append(Segment(f"{byte:02x}", style))
            else:
                segments.append(Segment("  "))

            if i == 7:
                segments.append(Segment("  "))
            elif i < BYTES_PER_ROW - 1:
                segments.append(Segment(" "))

        segments.append(Segment("  |", Style.parse("bright_black")))

        for i, byte in enumerate(row_bytes):
            byte_pos = offset + i
            char = chr(byte) if 32 <= byte <= 126 else "."
            is_cursor = byte_pos == self.cursor_pos
            is_modified = byte_pos < len(self.original) and byte != self.original[byte_pos]
            is_selected = sel is not None and sel[0] <= byte_pos <= sel[1]

            if is_cursor and self.edit_pane == "ascii":
                style = Style.parse("black on cyan bold")
            elif is_selected:
                style = Style.parse("black on bright_cyan")
            elif is_modified:
                style = Style.parse("bright_red")
            elif byte < 32 or byte == 127:
                style = Style.parse("bright_black")
            else:
                style = Style.parse("white")

            segments.append(Segment(char, style))

        if len(row_bytes) < BYTES_PER_ROW:
            segments.append(Segment(" " * (BYTES_PER_ROW - len(row_bytes))))

        segments.append(Segment("|", Style.parse("bright_black")))
        return Strip(segments)

    # ── Scrolling ──────────────────────────────────────────────────────────────

    def _scroll_to_row(self, row: int) -> None:
        max_top = max(0, self._total_rows() - self.size.height)
        self.view_top = max(0, min(max_top, row))
        self.refresh()

    def _scroll_by(self, delta: int) -> None:
        self._scroll_to_row(self.view_top + delta)

    def on_mouse_scroll_up(self, event: events.MouseScrollUp) -> None:
        self._scroll_by(-3)
        event.stop()

    def on_mouse_scroll_down(self, event: events.MouseScrollDown) -> None:
        self._scroll_by(3)
        event.stop()

    def on_mouse_down(self, event: events.MouseDown) -> None:
        if event.button == 1:
            idx = self._xy_to_byte_index(event.x, event.y)
            if idx is not None:
                self._sel_anchor = idx
                self._sel_end = idx
                self._dragging = True
                self.refresh()
                self._post_selection()
        event.stop()

    def on_mouse_move(self, event: events.MouseMove) -> None:
        if self._dragging and event.button == 1:
            idx = self._xy_to_byte_index(event.x, event.y)
            if idx is not None and idx != self._sel_end:
                self._sel_end = idx
                self.refresh()
                self._post_selection()

    def on_mouse_up(self, event: events.MouseUp) -> None:
        self._dragging = False

    def _post_selection(self) -> None:
        self.post_message(self.SelectionChanged(self.sel_range()))

    # ── Keyboard input ─────────────────────────────────────────────────────────

    def on_key(self, event: events.Key) -> None:
        if getattr(self.app, "_save_state", None) is not None:
            return

        key = event.key

        if key == "tab":
            event.prevent_default()
            event.stop()
            self.edit_pane = "ascii" if self.edit_pane == "hex" else "hex"
            self.pending_nibble = None
            self.refresh()
            self._post_cursor()
            return

        nav = {
            "up":       -BYTES_PER_ROW,
            "down":     +BYTES_PER_ROW,
            "left":     -1,
            "right":    +1,
            "numpad_8": -BYTES_PER_ROW,
            "numpad_2": +BYTES_PER_ROW,
            "numpad_4": -1,
            "numpad_6": +1,
        }
        if key in nav:
            self._move(nav[key])
            return
        if key == "pageup":
            self._move(-self.size.height * BYTES_PER_ROW)
            return
        if key == "pagedown":
            self._move(+self.size.height * BYTES_PER_ROW)
            return
        if key == "home":
            self._jump((self.cursor_pos // BYTES_PER_ROW) * BYTES_PER_ROW)
            return
        if key == "end":
            row_start = (self.cursor_pos // BYTES_PER_ROW) * BYTES_PER_ROW
            self._jump(min(len(self.data) - 1, row_start + BYTES_PER_ROW - 1))
            return
        if key == "ctrl+home":
            self._jump(0)
            return
        if key == "ctrl+end":
            self._jump(len(self.data) - 1)
            return

        char = event.character
        if char:
            if self.edit_pane == "hex" and char.lower() in "0123456789abcdef":
                event.stop()
                self._hex_input(int(char, 16))
            elif self.edit_pane == "ascii" and 32 <= ord(char) <= 126:
                event.stop()
                self._ascii_input(ord(char))

    def _move(self, delta: int) -> None:
        self.pending_nibble = None
        self._jump(max(0, min(len(self.data) - 1, self.cursor_pos + delta)))

    def _jump(self, pos: int) -> None:
        self.cursor_pos = pos
        self.pending_nibble = None
        self._ensure_visible()
        self.refresh()
        self._post_cursor()

    def _hex_input(self, nibble: int) -> None:
        if self.pending_nibble is None:
            self.pending_nibble = nibble
        else:
            self.data[self.cursor_pos] = (self.pending_nibble << 4) | nibble
            self.modified = True
            self.pending_nibble = None
            self.cursor_pos = min(len(self.data) - 1, self.cursor_pos + 1)
            self._ensure_visible()
        self.refresh()
        self._post_cursor()

    def _ascii_input(self, byte: int) -> None:
        self.data[self.cursor_pos] = byte
        self.modified = True
        self.cursor_pos = min(len(self.data) - 1, self.cursor_pos + 1)
        self._ensure_visible()
        self.refresh()
        self._post_cursor()

    def _ensure_visible(self) -> None:
        row = self.cursor_pos // BYTES_PER_ROW
        if row < self.view_top:
            self.view_top = row
        elif row >= self.view_top + self.size.height:
            self.view_top = row - self.size.height + 1
        max_top = max(0, self._total_rows() - self.size.height)
        self.view_top = max(0, min(max_top, self.view_top))

    def _entropy_window(self) -> bytearray:
        return self.data

    def _post_cursor(self) -> None:
        val = self.data[self.cursor_pos] if self.cursor_pos < len(self.data) else 0
        self.post_message(self.CursorMoved(self.cursor_pos, val, self.modified, self.edit_pane))
        self.post_message(self.EntropyUpdate(shannon_entropy(self._entropy_window())))

    # ── Save ───────────────────────────────────────────────────────────────────

    def save(self, path: Path) -> None:
        path.write_bytes(bytes(self.data))
        self.original = bytearray(self.data)
        self.modified = False
        self.refresh()
        self._post_cursor()


# ── Application ─────────────────────────────────────────────────────────────────

class HexEditApp(App):

    CSS = """
    Header {
        background: $panel;
    }
    Footer {
        background: $panel;
    }
    HexView {
        height: 1fr;
    }
    #statusbar {
        background: $surface;
        color: $primary;
        height: 1;
        padding: 0 1;
    }
    """

    BINDINGS = [
        ("ctrl+s", "save", "Save"),
        ("ctrl+c", "copy", "Copy"),
        ("ctrl+q", "quit_app", "Quit"),
    ]

    def __init__(self, filepath: Path) -> None:
        super().__init__()
        self.filepath = filepath
        self._data = bytearray(filepath.read_bytes())
        self._file_type = detect_file_type(self._data)
        self._save_state: str | None = None   # None | "prompt" | "copy_path" | "copy_fmt"
        self._copy_path_buf: str = ""
        self._last_cursor_event: HexView.CursorMoved | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield MagicBar(self._file_type)
        yield EntropyBar("")
        yield HexView(self._data, id="hexview")
        yield Static("", id="statusbar")
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"0xPeek — {self.filepath.name}"
        view = self.query_one("#hexview", HexView)
        view.focus()
        view._post_cursor()

    # ── Status bar ─────────────────────────────────────────────────────────────

    def _refresh_status(self) -> None:
        if self._last_cursor_event is None:
            return
        e = self._last_cursor_event
        bar = self.query_one("#statusbar", Static)
        modified = "  ● MODIFIED" if e.modified else ""
        pane = f"[{e.pane.upper()}]"
        bar.update(
            f"Offset: 0x{e.pos:08x}  ({e.pos:,})"
            f"  │  Value: 0x{e.byte_val:02x}  ({e.byte_val:d})"
            f"  │  Size: {len(self._data):,} B"
            f"  │  {pane}{modified}"
        )

    def on_hex_view_cursor_moved(self, event: HexView.CursorMoved) -> None:
        self._last_cursor_event = event
        if self._save_state is None:
            self._refresh_status()

    def _clipboard_write(self, text: str) -> None:
        try:
            subprocess.run(["pbcopy"], input=text.encode(), check=True)
        except Exception:
            pass

    def action_copy(self) -> None:
        view = self.query_one("#hexview", HexView)
        sel = view.sel_range()
        count = (sel[1] - sel[0] + 1) if sel else 1
        self._save_state = "copy_fmt"
        bar = self.query_one("#statusbar", Static)
        bar.update(
            f"[bold]Copy {count} byte{'s' if count != 1 else ''}:[/]  "
            "[bold yellow]\\[H][/] Hex   "
            "[bold cyan]\\[A][/] ASCII   "
            "[bright_black]\\[Esc][/] Cancel"
        )

    def on_hex_view_entropy_update(self, event: HexView.EntropyUpdate) -> None:
        self.query_one(EntropyBar).update_entropy(event.entropy)

    def on_hex_view_selection_changed(self, event: HexView.SelectionChanged) -> None:
        if self._save_state is not None:
            return
        bar = self.query_one("#statusbar", Static)
        if event.sel is None:
            self._refresh_status()
        else:
            lo, hi = event.sel
            count = hi - lo + 1
            bar.update(
                f"[bold cyan]Selected:[/] 0x{lo:08x} – 0x{hi:08x}"
                f"  [bright_black]│[/]  {count:,} byte{'s' if count != 1 else ''}"
                f"  [bright_black]│[/]  Ctrl+C to copy"
            )

    # ── Save flow ──────────────────────────────────────────────────────────────

    def action_save(self) -> None:
        view = self.query_one("#hexview", HexView)
        if not view.modified:
            return
        self._save_state = "prompt"
        bar = self.query_one("#statusbar", Static)
        bar.update(
            "[bold]Save:[/]  "
            "[bold yellow]\\[O][/] Overwrite original   "
            "[bold cyan]\\[C][/] Save as copy   "
            "[bright_black]\\[Esc][/] Cancel"
        )

    def on_key(self, event: events.Key) -> None:
        if self._save_state == "prompt":
            event.stop()
            if event.key == "o":
                self._save_state = None
                self.query_one("#hexview", HexView).save(self.filepath)
                self._refresh_status()
            elif event.key == "c":
                self._save_state = "copy_path"
                stem = self.filepath.stem
                suffix = self.filepath.suffix
                self._copy_path_buf = str(
                    self.filepath.with_name(f"{stem}_copy{suffix}")
                )
                self._update_copy_prompt()
            elif event.key == "escape":
                self._save_state = None
                self._refresh_status()

        elif self._save_state == "copy_fmt":
            event.stop()
            bar = self.query_one("#statusbar", Static)
            view = self.query_one("#hexview", HexView)
            sel = view.sel_range()
            # Fall back to single byte under cursor if no selection
            if sel is None and self._last_cursor_event is not None:
                e = self._last_cursor_event
                sel = (e.pos, e.pos)
            if event.key == "h" and sel is not None:
                chunk = view.data[sel[0]:sel[1] + 1]
                text = "".join(f"\\x{b:02x}" for b in chunk)
                self._clipboard_write(text)
                self._save_state = None
                preview = text if len(text) <= 40 else text[:40] + "…"
                bar.update(f"[bold green]Copied hex ({len(chunk)}B):[/] [white]{preview}[/]")
                self.call_later(self._refresh_status)
            elif event.key == "a" and sel is not None:
                chunk = view.data[sel[0]:sel[1] + 1]
                text = "".join(chr(b) if 32 <= b <= 126 else f"\\x{b:02x}" for b in chunk)
                self._clipboard_write(text)
                self._save_state = None
                preview = text if len(text) <= 40 else text[:40] + "…"
                bar.update(f"[bold green]Copied ASCII ({len(chunk)}B):[/] [white]{preview}[/]")
                self.call_later(self._refresh_status)
            elif event.key == "escape":
                self._save_state = None
                self._refresh_status()

        elif self._save_state == "copy_path":
            event.stop()
            if event.key == "enter":
                dest = Path(self._copy_path_buf.strip())
                self._save_state = None
                dest.write_bytes(bytes(self.query_one("#hexview", HexView).data))
                bar = self.query_one("#statusbar", Static)
                bar.update(f"[bold green]Copy saved → {dest}[/]")
                self.call_later(self._refresh_status)
            elif event.key == "escape":
                self._save_state = None
                self._refresh_status()
            elif event.key == "backspace":
                self._copy_path_buf = self._copy_path_buf[:-1]
                self._update_copy_prompt()
            elif event.character and ord(event.character) >= 32:
                self._copy_path_buf += event.character
                self._update_copy_prompt()

    def _update_copy_prompt(self) -> None:
        bar = self.query_one("#statusbar", Static)
        bar.update(
            f"[bold]Save copy to:[/] [white]{self._copy_path_buf}[/][bright_yellow]█[/]  "
            "[bright_black]Enter to confirm · Esc to cancel[/]"
        )

    def action_quit_app(self) -> None:
        view = self.query_one("#hexview", HexView)
        if view.modified:
            bar = self.query_one("#statusbar", Static)
            bar.update("Unsaved changes! Press Ctrl+Q again to force quit, or Ctrl+S to save.")
            view.modified = False
        else:
            self.exit()


# ── Entry point ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="0xPeek",
        description="A terminal hex editor for reverse engineering and malware analysis.",
    )
    parser.add_argument("file", help="Path to the file to view/edit")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"0xPeek: '{path}': No such file", file=sys.stderr)
        sys.exit(1)
    if not path.is_file():
        print(f"0xPeek: '{path}': Not a regular file", file=sys.stderr)
        sys.exit(1)

    HexEditApp(path).run()


if __name__ == "__main__":
    main()
