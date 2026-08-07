#!/usr/bin/env python3
"""Norton Commander style interactive tree browser for the static scanner.

A blue full-screen TUI (curses) that lets you walk a source tree and fire the
static scanner from the keyboard, DOS-Commander style:

    ↑/↓ · PgUp/PgDn · Home/End   move the selection bar
    Enter                         open a directory (or view a scanned file)
    Backspace / ←                 go up one directory
    F3 / v                        view the selected file (findings first)
    F4 / f                        jump to the findings report for the selection
    F5 / s                        scan the selected file or directory
    F2 / a                        scan every file under the current directory
    Tab                           toggle the results panel
    ~                             command line: type and run a shell command
    F1 / h                        help
    F10 / q                       quit

It reuses the same engine as ``--scan-dir`` (core.staticScanner), so a scan
here reports exactly what the batch scan would. This is a thin, dependency-free
view layer; all the detection logic lives in the scanner.
"""

import os
import curses

from core.staticScanner import (
    collectFiles, scanFile, detectLanguage, loadIgnorePatterns,
    SKIP_DIRS, SKIP_FILE_RE, MAX_FILE_SIZE,
)

SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
SORT_MODES = ['name', 'severity', 'size']

# ---- curses color-pair ids (Norton Commander blue theme) -----------------
CP_PANEL = 1     # white on blue        normal rows / panel body
CP_SELECT = 2    # black on cyan        selection bar
CP_FRAME = 3     # cyan on blue         box drawing
CP_HEADER = 4    # yellow on blue       titles / dir names
CP_KEYNUM = 5    # white on black       function-key numbers
CP_KEYLBL = 6    # black on cyan        function-key labels
CP_CRIT = 7      # red on blue
CP_MED = 8       # yellow on blue
CP_CLEAN = 9     # green on blue
CP_STATUS = 10   # black on cyan        top status line

SEVERITY_CP = {
    'CRITICAL': CP_CRIT, 'HIGH': CP_CRIT,
    'MEDIUM': CP_MED, 'LOW': CP_CLEAN,
}

# Bottom function-key bar: (key, label).
FKEYS = [
    ('1', 'Help'), ('2', 'ScanAll'), ('3', 'View'), ('4', 'Finds'),
    ('5', 'Scan'), ('9', 'Sort'), ('10', 'Quit'),
]


def _human_size(n):
    for unit in ('', 'K', 'M', 'G'):
        if n < 1024:
            return ('%d%s' % (n, unit)) if unit == '' else ('%.0f%s' % (n, unit))
        n /= 1024.0
    return '%.0fT' % n


def _worst(findings):
    worst = None
    for f in findings:
        rank = SEVERITY_ORDER.index(f.severity)
        worst = rank if worst is None else min(worst, rank)
    return None if worst is None else SEVERITY_ORDER[worst]


class Entry(object):
    __slots__ = ('name', 'path', 'is_dir', 'is_parent')

    def __init__(self, name, path, is_dir, is_parent=False):
        self.name = name
        self.path = path
        self.is_dir = is_dir
        self.is_parent = is_parent


class NCBrowser(object):
    """Stateful full-screen browser. Call :meth:`run` inside curses.wrapper."""

    def __init__(self, screen, root, include_unknown=False,
                 min_severity='LOW', json_out=None):
        self.scr = screen
        self.root = os.path.abspath(root)
        self.cwd = self.root
        self.include_unknown = include_unknown
        self.sort_mode = 'name'   # name | severity | size  (F9 cycles)
        try:                      # min severity to *display* (LOW == show all)
            self.min_sev_idx = SEVERITY_ORDER.index((min_severity or 'LOW').upper())
        except ValueError:
            self.min_sev_idx = len(SEVERITY_ORDER) - 1
        self.json_out = json_out or 'xsstrike-report.json'
        self.sel = 0            # index of the selection bar
        self.top = 0            # first visible row (scroll offset)
        self.entries = []
        self.results = {}       # abspath -> [Finding]  (persists across dirs)
        self.scanned = set()    # abspath of files that have been scanned
        self.message = ''       # transient status message
        self.show_panel = True  # results panel visibility
        self.ignore = loadIgnorePatterns(self.root)
        self._load_dir(self.cwd)

    # ---- severity filter ---------------------------------------------------
    def _visible(self, findings):
        """Findings at or above the current minimum-severity filter."""
        return [f for f in findings
                if SEVERITY_ORDER.index(f.severity) <= self.min_sev_idx]

    # ---- directory listing -------------------------------------------------
    def _scannable_file(self, name, full):
        if SKIP_FILE_RE.search(name):
            return False
        rel = os.path.relpath(full, self.root)
        import fnmatch
        if any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p) for p in self.ignore):
            return False
        if detectLanguage(full) is None and not self.include_unknown:
            return False
        try:
            if os.path.getsize(full) > MAX_FILE_SIZE:
                return False
        except OSError:
            return False
        return True

    def _load_dir(self, path):
        self.cwd = os.path.abspath(path)
        dirs, files = [], []
        try:
            names = os.listdir(self.cwd)
        except OSError as exc:
            self.message = 'Cannot open: %s' % exc
            names = []
        for name in names:
            full = os.path.join(self.cwd, name)
            if os.path.isdir(full):
                if name in SKIP_DIRS or name.startswith('.'):
                    continue
                dirs.append(Entry(name, full, True))
            elif self._scannable_file(name, full):
                files.append(Entry(name, full, False))
        self.entries = []
        if self.cwd != self.root and os.path.dirname(self.cwd) != self.cwd:
            self.entries.append(Entry('..', os.path.dirname(self.cwd), True, True))
        self.entries += dirs + files
        self._apply_sort()
        self.sel = 0
        self.top = 0

    # ---- sorting -----------------------------------------------------------
    def _safe_size(self, path):
        try:
            return os.path.getsize(path)
        except OSError:
            return 0

    def _file_sev_rank(self, path):
        fs = self._visible(self.results.get(path, [])) if path in self.scanned else []
        worst = _worst(fs)
        return SEVERITY_ORDER.index(worst) if worst is not None else 99

    def _dir_sev_rank(self, path):
        best = 99
        prefix = path.rstrip(os.sep) + os.sep
        for p, fs in self.results.items():
            if p.startswith(prefix):
                worst = _worst(self._visible(fs))
                if worst is not None:
                    best = min(best, SEVERITY_ORDER.index(worst))
        return best

    def _apply_sort(self):
        """Reorder ``self.entries`` in place: '..' first, dirs, then files."""
        parent = [e for e in self.entries if e.is_parent]
        dirs = [e for e in self.entries if e.is_dir and not e.is_parent]
        files = [e for e in self.entries if not e.is_dir]
        if self.sort_mode == 'severity':
            dirs.sort(key=lambda e: (self._dir_sev_rank(e.path), e.name.lower()))
            files.sort(key=lambda e: (self._file_sev_rank(e.path), e.name.lower()))
        elif self.sort_mode == 'size':
            dirs.sort(key=lambda e: e.name.lower())
            files.sort(key=lambda e: (-self._safe_size(e.path), e.name.lower()))
        else:  # name
            dirs.sort(key=lambda e: e.name.lower())
            files.sort(key=lambda e: e.name.lower())
        self.entries = parent + dirs + files

    # ---- scanning ----------------------------------------------------------
    def _files_under(self, path):
        """Yield scannable (path, lang) pairs under a dir, or the file itself."""
        if os.path.isdir(path):
            for full, lang in collectFiles(path, self.include_unknown, self.ignore):
                yield full, lang
        else:
            lang = detectLanguage(path) or 'unknown'
            yield os.path.abspath(path), lang

    def _scan(self, path, label):
        targets = list(self._files_under(path))
        if not targets:
            self.message = 'Nothing scannable in %s' % os.path.basename(path)
            return
        total = len(targets)
        found = 0
        for i, (full, lang) in enumerate(targets, 1):
            if i % 5 == 0 or i == total:
                self._flash('Scanning %s  [%d/%d]  %d findings'
                            % (label, i, total, found))
            fs = scanFile(full, lang)
            self.results[full] = fs
            self.scanned.add(full)
            found += len(fs)
        self.message = 'Scanned %s: %d file(s), %d finding(s)' % (label, total, found)

    def _scan_selected(self):
        e = self._current()
        if e is None or e.is_parent:
            return
        self._scan(e.path, e.name)

    def _scan_all(self):
        self._scan(self.cwd, os.path.basename(self.cwd) or self.cwd)

    # ---- geometry ----------------------------------------------------------
    def _current(self):
        return self.entries[self.sel] if self.entries else None

    def _list_height(self, h):
        # rows 0=status, 1=top frame ... last two = bottom frame + key bar
        panel = 8 if self.show_panel else 0
        return max(1, h - 4 - panel)

    # ---- annotations -------------------------------------------------------
    def _file_annot(self, path):
        if path not in self.scanned:
            return ' ', CP_PANEL
        fs = self._visible(self.results.get(path, []))
        if not fs:
            return '✓', CP_CLEAN            # ✓
        sev = _worst(fs)
        return '✗%d' % len(fs), SEVERITY_CP[sev]   # ✗n

    def _dir_annot(self, path):
        total = 0
        worst = None
        for p, fs in self.results.items():
            if p.startswith(path + os.sep):
                fs = self._visible(fs)
                total += len(fs)
                s = _worst(fs)
                if s is not None:
                    r = SEVERITY_ORDER.index(s)
                    worst = r if worst is None else min(worst, r)
        if not total:
            return '', CP_PANEL
        cp = SEVERITY_CP[SEVERITY_ORDER[worst]] if worst is not None else CP_CRIT
        return '✗%d' % total, cp

    # ---- rendering ---------------------------------------------------------
    def _draw(self):
        self.scr.erase()
        h, w = self.scr.getmaxyx()
        w = max(w, 20)
        self._draw_status(w)
        self._draw_frame(h, w)
        self._draw_list(h, w)
        if self.show_panel:
            self._draw_results(h, w)
        self._draw_keys(h, w)
        self.scr.noutrefresh()
        curses.doupdate()

    def _addstr(self, y, x, text, cp, attr=0, width=None):
        h, w = self.scr.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        if width is not None:
            text = text[:width].ljust(width)
        text = text[:max(0, w - x - 1)]
        try:
            self.scr.addstr(y, x, text, curses.color_pair(cp) | attr)
        except curses.error:
            pass

    def _status_indicator(self):
        parts = ['sort:%s' % self.sort_mode]
        if self.min_sev_idx < len(SEVERITY_ORDER) - 1:
            parts.append('sev>=%s' % SEVERITY_ORDER[self.min_sev_idx])
        if self.include_unknown:
            parts.append('all-files')
        return ' '.join(parts) + ' '

    def _draw_status(self, w):
        title = ' XSStrike Commander '
        ind = self._status_indicator()
        if w < len(title) + len(ind) + 12:   # no room -> drop the indicator
            ind = ''
        path = self.cwd
        avail = w - len(title) - 2 - (len(ind) + 1 if ind else 0)
        if avail > 3 and len(path) > avail:
            path = '...' + path[-(avail - 3):]
        line = (title + path).ljust(w - 1)
        self._addstr(0, 0, line, CP_STATUS, curses.A_BOLD, width=w - 1)
        if ind:
            self._addstr(0, max(0, w - 1 - len(ind)), ind, CP_STATUS, curses.A_BOLD)

    def _draw_frame(self, h, w):
        lh = self._list_height(h)
        top = 1
        bottom = top + lh + 1
        horiz = '═' * (w - 2)
        self._addstr(top, 0, '╔' + horiz + '╗', CP_FRAME, curses.A_BOLD)
        for y in range(top + 1, bottom):
            self._addstr(y, 0, '║', CP_FRAME, curses.A_BOLD)
            self._addstr(y, w - 1, '║', CP_FRAME, curses.A_BOLD)
        self._addstr(bottom, 0, '╚' + horiz + '╝', CP_FRAME, curses.A_BOLD)
        # column header inside the top frame
        hdr = ' Name'.ljust(w - 14) + 'Size  Stat '
        self._addstr(top, 2, hdr[:w - 4], CP_HEADER, curses.A_BOLD)

    def _draw_list(self, h, w):
        lh = self._list_height(h)
        if self.sel < self.top:
            self.top = self.sel
        elif self.sel >= self.top + lh:
            self.top = self.sel - lh + 1
        inner = w - 2
        for i in range(lh):
            idx = self.top + i
            y = 2 + i
            if idx >= len(self.entries):
                self._addstr(y, 1, ' ' * inner, CP_PANEL)
                continue
            e = self.entries[idx]
            selected = idx == self.sel
            base_cp = CP_SELECT if selected else CP_PANEL
            attr = curses.A_BOLD if selected else 0

            if e.is_parent:
                name = '/..'
                size = ''
                annot, acp = '', base_cp
            elif e.is_dir:
                name = '/' + e.name
                size = ''
                annot, acp = self._dir_annot(e.path)
            else:
                name = ' ' + e.name
                try:
                    size = _human_size(os.path.getsize(e.path))
                except OSError:
                    size = '?'
                annot, acp = self._file_annot(e.path)

            name_w = inner - 12
            label = name[:name_w].ljust(name_w)
            row = label + size.rjust(6) + '  '
            self._addstr(y, 1, row.ljust(inner), base_cp, attr)
            # status glyph in its own colour (unless selected -> keep bar colour)
            if annot:
                acp = base_cp if selected else acp
                self._addstr(y, 1 + inner - 4, annot[:4].ljust(4),
                             acp, attr | (0 if selected else curses.A_BOLD))

    def _draw_results(self, h, w):
        lh = self._list_height(h)
        top = 2 + lh + 1
        self._addstr(top, 0, '─' * w, CP_FRAME)
        e = self._current()
        lines = self._detail_lines(e, w)
        for i in range(6):
            y = top + 1 + i
            text = lines[i] if i < len(lines) else ''
            cp = CP_PANEL
            attr = 0
            if text.startswith('\x00'):     # severity-tagged line
                tag, text = text[1:].split('\x01', 1)
                cp = SEVERITY_CP.get(tag, CP_PANEL)
                attr = curses.A_BOLD
            self._addstr(y, 0, ' ' + text, cp, attr, width=w - 1)

    def _detail_lines(self, e, w):
        if e is None or e.is_parent:
            return ['Select a file or directory, then press F5 to scan.']
        if e.is_dir:
            annot, _ = self._dir_annot(e.path)
            head = 'DIR  %s/' % e.name
            if annot:
                return [head, '%s findings under this directory (F5 to (re)scan)' % annot[1:]]
            return [head, 'Not scanned yet — F5 scans this dir, F2 scans everything.']
        if e.path not in self.scanned:
            return ['FILE %s' % e.name, 'Not scanned yet — press F5 to scan.']
        fs = self._visible(self.results.get(e.path, []))
        if not fs:
            return ['\x00LOW\x01FILE %s — clean, no issues found.' % e.name]
        fs = sorted(fs, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.line_no))
        out = ['%s — %d finding(s):' % (e.name, len(fs))]
        for f in fs[:5]:
            out.append('\x00%s\x01[%s] line %d  %s (%s)'
                       % (f.severity, f.severity, f.line_no, f.name, f.cwe))
        if len(fs) > 5:
            out.append('  ... %d more — press F4 for the full report.' % (len(fs) - 5))
        return out

    def _draw_keys(self, h, w):
        y = h - 1
        x = 0
        self._addstr(y, 0, ' ' * (w - 1), CP_KEYLBL)
        for key, label in FKEYS:
            cell = 'F%s' % key
            self._addstr(y, x, cell, CP_KEYNUM, curses.A_BOLD)
            x += len(cell)
            lab = label + ' '
            self._addstr(y, x, lab, CP_KEYLBL)
            x += len(lab)
            if x >= w - 6:
                break

    def _flash(self, text):
        """Immediately paint a status message (used during a blocking scan)."""
        h, w = self.scr.getmaxyx()
        self.message = text
        self._addstr(0, 0, (' ' + text).ljust(w - 1), CP_STATUS, curses.A_BOLD, width=w - 1)
        self.scr.noutrefresh()
        curses.doupdate()

    # ---- full-screen views -------------------------------------------------
    def _pager(self, title, lines):
        h, w = self.scr.getmaxyx()
        off = 0
        body = h - 2
        while True:
            self.scr.erase()
            self._addstr(0, 0, (' ' + title).ljust(w - 1), CP_STATUS, curses.A_BOLD, width=w - 1)
            for i in range(body):
                if off + i >= len(lines):
                    break
                text = lines[off + i]
                cp, attr = CP_PANEL, 0
                if text.startswith('\x00'):
                    tag, text = text[1:].split('\x01', 1)
                    cp = SEVERITY_CP.get(tag, CP_PANEL)
                    attr = curses.A_BOLD
                self._addstr(1 + i, 0, text, cp, attr, width=w - 1)
            hint = ' ↑/↓ PgUp/PgDn scroll · Esc/q back '
            self._addstr(h - 1, 0, hint.ljust(w - 1), CP_KEYLBL, width=w - 1)
            self.scr.noutrefresh()
            curses.doupdate()
            c = self.scr.getch()
            if c in (ord('q'), 27, curses.KEY_F3, curses.KEY_F4, ord('\n')):
                return
            elif c in (curses.KEY_DOWN, ord('j')):
                off = min(off + 1, max(0, len(lines) - body))
            elif c in (curses.KEY_UP, ord('k')):
                off = max(0, off - 1)
            elif c == curses.KEY_NPAGE:
                off = min(off + body, max(0, len(lines) - body))
            elif c == curses.KEY_PPAGE:
                off = max(0, off - body)
            elif c == curses.KEY_HOME:
                off = 0
            elif c == curses.KEY_END:
                off = max(0, len(lines) - body)

    def _view_file(self):
        e = self._current()
        if e is None or e.is_dir:
            self.message = 'Not a file.'
            return
        lines = []
        fs = sorted(self._visible(self.results.get(e.path, [])),
                    key=lambda f: (SEVERITY_ORDER.index(f.severity), f.line_no))
        flagged = {f.line_no for f in fs}
        if fs:
            lines.append('\x00%s\x01=== %d finding(s) ===' % (fs[0].severity, len(fs)))
            for f in fs:
                lines.append('\x00%s\x01  [%s] line %d  %s (%s)'
                             % (f.severity, f.severity, f.line_no, f.name, f.cwe))
                lines.append('           %s' % f.desc)
            lines.append('')
        try:
            with open(e.path, 'r', encoding='utf-8', errors='ignore') as fh:
                src = fh.readlines()
        except OSError as exc:
            src = ['<cannot read file: %s>' % exc]
        for n, line in enumerate(src, 1):
            text = '%5d  %s' % (n, line.rstrip('\n'))
            if n in flagged:
                sev = next(f.severity for f in fs if f.line_no == n)
                text = '\x00%s\x01%s' % (sev, text)
            lines.append(text)
        self._pager('View: %s' % e.name, lines)

    def _findings_report(self):
        e = self._current()
        target = e.path if (e and not e.is_parent) else self.cwd
        rows = []
        for p in sorted(self.results):
            if p == target or p.startswith(target.rstrip(os.sep) + os.sep) or not os.path.isdir(target):
                if not (p == target or p.startswith(target.rstrip(os.sep) + os.sep)):
                    continue
                rows.extend(self._visible(self.results[p]))
        if not rows:
            self.message = 'No findings for the selection — scan it first (F5).'
            return
        rows.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.path, f.line_no))
        lines = ['Findings under %s' % target, '']
        for f in rows:
            rel = os.path.relpath(f.path, self.root)
            lines.append('\x00%s\x01[%s] %s (%s)' % (f.severity, f.severity, f.name, f.cwe))
            lines.append('        %s:%d' % (rel, f.line_no))
            lines.append('        %s' % f.snippet)
            lines.append('')
        self._pager('Findings (%d)' % len(rows), lines)

    # ---- interactive feature toggles --------------------------------------
    def _cycle_sort(self):
        cur = self._current()
        self.sort_mode = SORT_MODES[(SORT_MODES.index(self.sort_mode) + 1)
                                    % len(SORT_MODES)]
        self._apply_sort()
        self.sel, self.top = 0, 0
        if cur is not None:                 # keep the bar on the same entry
            for i, e in enumerate(self.entries):
                if e.path == cur.path:
                    self.sel = i
                    break
        self.message = 'Sorted by %s' % self.sort_mode

    def _cycle_severity(self):
        self.min_sev_idx = (self.min_sev_idx + 1) % len(SEVERITY_ORDER)
        if self.sort_mode == 'severity':    # ranks depend on the filter
            self._apply_sort()
        if self.min_sev_idx == len(SEVERITY_ORDER) - 1:
            self.message = 'Severity filter: showing all findings'
        else:
            self.message = ('Severity filter: %s and above'
                            % SEVERITY_ORDER[self.min_sev_idx])

    def _toggle_unknown(self):
        self.include_unknown = not self.include_unknown
        self._load_dir(self.cwd)
        self.message = ('Now listing/scanning unknown file types'
                        if self.include_unknown else
                        'Ignoring unknown file types')

    def _export_json(self):
        import json
        findings = []
        for p in sorted(self.results):
            findings.extend(self._visible(self.results[p]))
        if not findings:
            self.message = ('Nothing to export — scan first (F5/F2) '
                            'or lower the severity filter (m).')
            return
        findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity),
                                     f.path, f.line_no))
        dest = self._prompt_text('Write JSON report to', self.json_out)
        if not dest:
            self.message = 'Export cancelled.'
            return
        self.json_out = dest
        counts = {level: 0 for level in SEVERITY_ORDER}
        for f in findings:
            counts[f.severity] += 1
        report = dict(
            target=self.root,
            files_scanned=len(self.scanned),
            total_findings=len(findings),
            summary=counts,
            findings=[f.as_dict() for f in findings],
        )
        path = dest if os.path.isabs(dest) else os.path.join(self.cwd, dest)
        try:
            with open(path, 'w', encoding='utf-8') as handle:
                json.dump(report, handle, indent=2)
            self.message = 'Wrote %d finding(s) to %s' % (len(findings), path)
        except (IOError, OSError) as exc:
            self.message = 'Export failed: %s' % exc

    def _prompt_text(self, label, default=''):
        """Read a single line at the bottom of the screen. Esc returns None."""
        h, w = self.scr.getmaxyx()
        buf = default
        curses.curs_set(1)
        try:
            while True:
                y = h - 2
                shown = '%s: %s' % (label, buf)
                if len(shown) > w - 1:
                    shown = shown[len(shown) - (w - 1):]
                self._addstr(y, 0, shown.ljust(w - 1), CP_STATUS, width=w - 1)
                try:
                    self.scr.move(y, min(len(shown), w - 2))
                except curses.error:
                    pass
                self.scr.noutrefresh()
                curses.doupdate()
                c = self.scr.getch()
                if c == 27:                                   # Esc — cancel
                    return None
                if c in (ord('\n'), curses.KEY_ENTER):
                    return buf.strip()
                if c in (curses.KEY_BACKSPACE, 127, 8):
                    buf = buf[:-1]
                elif 32 <= c < 127:
                    buf += chr(c)
        finally:
            curses.curs_set(0)

    def _help(self):
        lines = [
            'XSStrike Commander — keyboard reference', '',
            '  Up / Down         move the selection bar',
            '  PgUp / PgDn       move a page at a time',
            '  Home / End        jump to first / last entry',
            '  Enter             open directory  /  view scanned file',
            '  Backspace / Left  go up to the parent directory',
            '',
            '  F5  / s           scan the selected file or directory',
            '  F2  / a           scan EVERYTHING under the current directory',
            '  F3  / v           view the selected file (findings highlighted)',
            '  F4  / f           open the findings report for the selection',
            '  F9  / o           sort:  name -> severity -> size',
            '  m                 min-severity filter (hide lower findings)',
            '  e                 export findings to a JSON report file',
            '  u                 toggle listing/scanning of unknown file types',
            '  Tab               show / hide the results panel',
            '  ~                 command line: type a shell command, run it',
            '                    in this directory (Esc cancels)',
            '  F1  / h           this help',
            '  F10 / q           quit',
            '',
            'Status glyphs:  ✓ clean   ✗N N findings   (blank) not scanned',
            'Findings use the same engine as  xsstrike --scan-dir.',
        ]
        self._pager('Help', lines)

    # ---- main loop ---------------------------------------------------------
    def _open_selected(self):
        e = self._current()
        if e is None:
            return
        if e.is_dir:
            self._load_dir(e.path)
        else:
            self._view_file()

    def _up(self):
        parent = os.path.dirname(self.cwd)
        if self.cwd != self.root and parent and parent != self.cwd:
            prev = os.path.basename(self.cwd)
            self._load_dir(parent)
            for i, e in enumerate(self.entries):
                if e.name == prev:
                    self.sel = i
                    break

    # ---- command line (NC-style shell prompt) ------------------------------
    def _command_line(self):
        """Read a shell command at the bottom of the screen and run it.

        Norton Commander's command line: press ``~`` to type a command, Enter
        runs it in the current directory, Esc cancels. The command runs with
        curses suspended so you get a real terminal — live output and even
        interactive programs work — then control returns to the browser.
        """
        h, w = self.scr.getmaxyx()
        prompt = (os.path.basename(self.cwd) or self.cwd) + '$ '
        buf = ''
        curses.curs_set(1)
        try:
            while True:
                y = h - 2
                shown = prompt + buf
                # keep the tail visible if the line is longer than the screen
                if len(shown) > w - 1:
                    shown = shown[len(shown) - (w - 1):]
                self._addstr(y, 0, shown.ljust(w - 1), CP_STATUS, width=w - 1)
                try:
                    self.scr.move(y, min(len(shown), w - 2))
                except curses.error:
                    pass
                self.scr.noutrefresh()
                curses.doupdate()
                c = self.scr.getch()
                if c == 27:                                   # Esc — cancel
                    return
                if c in (ord('\n'), curses.KEY_ENTER):
                    break
                if c in (curses.KEY_BACKSPACE, 127, 8):
                    buf = buf[:-1]
                elif c == curses.KEY_UP or c == curses.KEY_DOWN:
                    pass                                      # no history (yet)
                elif 32 <= c < 127:
                    buf += chr(c)
        finally:
            curses.curs_set(0)

        cmd = buf.strip()
        if cmd:
            self._run_shell(cmd)
            self._load_dir(self.cwd)   # files may have changed; refresh listing

    def _run_shell(self, cmd):
        """Run ``cmd`` in a real terminal, then wait and restore the browser."""
        import subprocess
        curses.def_prog_mode()   # remember curses state
        curses.endwin()          # hand the terminal back to the shell
        try:
            print('\n\033[36m%s$\033[0m %s' % (self.cwd, cmd))
            try:
                subprocess.call(cmd, shell=True, cwd=self.cwd)
            except Exception as exc:   # keep the browser alive on any failure
                print('command failed: %s' % exc)
            try:
                input('\n[Press Enter to return to XSStrike Commander] ')
            except (EOFError, KeyboardInterrupt):
                pass
        finally:
            curses.reset_prog_mode()   # back into curses
            self.scr.refresh()

    def run(self):
        while True:
            self._draw()
            c = self.scr.getch()
            n = len(self.entries)
            lh = self._list_height(self.scr.getmaxyx()[0])
            self.message = ''
            if c in (curses.KEY_DOWN, ord('j')):
                self.sel = min(self.sel + 1, n - 1) if n else 0
            elif c in (curses.KEY_UP, ord('k')):
                self.sel = max(self.sel - 1, 0)
            elif c == curses.KEY_NPAGE:
                self.sel = min(self.sel + lh, n - 1) if n else 0
            elif c == curses.KEY_PPAGE:
                self.sel = max(self.sel - lh, 0)
            elif c == curses.KEY_HOME:
                self.sel = 0
            elif c == curses.KEY_END:
                self.sel = max(0, n - 1)
            elif c in (ord('\n'), curses.KEY_ENTER):
                self._open_selected()
            elif c in (curses.KEY_BACKSPACE, 127, 8, curses.KEY_LEFT):
                self._up()
            elif c in (curses.KEY_F5, ord('s')):
                self._scan_selected()
            elif c in (curses.KEY_F2, ord('a')):
                self._scan_all()
            elif c in (curses.KEY_F3, ord('v')):
                self._view_file()
            elif c in (curses.KEY_F4, ord('f')):
                self._findings_report()
            elif c in (curses.KEY_F1, ord('h'), ord('?')):
                self._help()
            elif c in (curses.KEY_F9, ord('o')):
                self._cycle_sort()
            elif c == ord('m'):
                self._cycle_severity()
            elif c == ord('e'):
                self._export_json()
            elif c == ord('u'):
                self._toggle_unknown()
            elif c == ord('\t'):
                self.show_panel = not self.show_panel
            elif c == ord('~'):
                self._command_line()
            elif c in (curses.KEY_F10, ord('q'), 27):
                break


def _init_colors():
    curses.start_color()
    try:
        curses.use_default_colors()
    except curses.error:
        pass
    B = curses.COLOR_BLUE
    curses.init_pair(CP_PANEL, curses.COLOR_WHITE, B)
    curses.init_pair(CP_SELECT, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(CP_FRAME, curses.COLOR_CYAN, B)
    curses.init_pair(CP_HEADER, curses.COLOR_YELLOW, B)
    curses.init_pair(CP_KEYNUM, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(CP_KEYLBL, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(CP_CRIT, curses.COLOR_RED, B)
    curses.init_pair(CP_MED, curses.COLOR_YELLOW, B)
    curses.init_pair(CP_CLEAN, curses.COLOR_GREEN, B)
    curses.init_pair(CP_STATUS, curses.COLOR_BLACK, curses.COLOR_CYAN)


def browse(root, include_unknown=False, min_severity='LOW', json_out=None):
    """Launch the Norton Commander style browser rooted at ``root``.

    ``include_unknown``, ``min_severity`` and ``json_out`` seed the same
    options exposed by ``--scan-all-files``, ``--min-severity`` and
    ``--json-out``; all three stay adjustable from inside the browser.

    Returns a process exit code (0 always; the browser is interactive).
    """
    if not os.path.isdir(root):
        print('Not a directory: %s' % root)
        return 2

    def _main(screen):
        curses.curs_set(0)
        _init_colors()
        screen.bkgd(' ', curses.color_pair(CP_PANEL))
        screen.keypad(True)
        NCBrowser(screen, root, include_unknown, min_severity, json_out).run()

    curses.wrapper(_main)
    return 0
