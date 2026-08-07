#!/usr/bin/env python3
"""Live directory-tree view for the --scan-dir mode.

Renders the directory being scanned as a tree once, then updates each file's
status in place (pending -> scanning -> clean/findings) using ANSI cursor
movement, and rolls the finding totals up onto the parent directories when the
scan finishes. Falls back cleanly: the caller only builds a tree when writing
to an interactive terminal and the tree fits on screen.
"""

import os
import sys
import shutil

from core.colors import green, red, yellow, grey, end

# Highest-severity-wins ordering, mirrors modes/codeScan.py.
_SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
_SEVERITY_COLOR = {
    'CRITICAL': red,
    'HIGH': red,
    'MEDIUM': yellow,
    'LOW': green,
}

# Status glyphs.
_GLYPH_PENDING = grey + '·' + end
_GLYPH_SCANNING = yellow + '⟳' + end
_GLYPH_CLEAN = green + '✓' + end

_MIN_ANNOT = 14  # columns reserved on the right for the status column


def _worst(findings):
    """Return the most severe severity label among ``findings`` (or None)."""
    worst = None
    for finding in findings:
        rank = _SEVERITY_ORDER.index(finding.severity)
        if worst is None or rank < worst:
            worst = rank
    return None if worst is None else _SEVERITY_ORDER[worst]


class ScanTree(object):
    """A tree of the scannable files, with per-file live status."""

    def __init__(self, root, files):
        self.root = os.path.abspath(root)
        self.rows = []          # list of {prefix, name, path, is_dir}
        self.row_of = {}        # abspath -> row index (files only)
        self.dir_files = {}     # dir-row index -> [descendant file abspaths]
        self.status = {}        # abspath -> 'pending'|'scanning'|'done'
        self.results = {}       # abspath -> list of Finding
        self._rendered = False

        paths = [p for p, _ in files]
        for path in paths:
            self.status[os.path.abspath(path)] = 'pending'
        self._build(paths)
        self.label_w = max((len(r['prefix']) + len(r['name'])
                            for r in self.rows), default=0)

    # ---- tree construction -------------------------------------------------
    def _build(self, paths):
        tree = {'dirs': {}, 'files': []}
        for path in paths:
            rel = os.path.relpath(os.path.abspath(path), self.root)
            parts = rel.split(os.sep)
            node = tree
            for part in parts[:-1]:
                node = node['dirs'].setdefault(part, {'dirs': {}, 'files': []})
            node['files'].append((parts[-1], os.path.abspath(path)))

        rootname = os.path.basename(self.root.rstrip(os.sep)) or self.root
        self.rows.append({'prefix': '', 'name': rootname + os.sep,
                          'path': None, 'is_dir': True})
        self.dir_files[0] = []
        self._render(tree, '', [0])

    def _render(self, node, prefix, ancestors):
        dirs = sorted(node['dirs'].items())
        files = sorted(node['files'])
        entries = ([('dir', name, sub) for name, sub in dirs]
                   + [('file', name, path) for name, path in files])
        for i, (kind, name, payload) in enumerate(entries):
            last = i == len(entries) - 1
            branch = '└─ ' if last else '├─ '
            cont = '   ' if last else '│  '
            row = len(self.rows)
            if kind == 'dir':
                self.rows.append({'prefix': prefix + branch, 'name': name + os.sep,
                                  'path': None, 'is_dir': True})
                self.dir_files[row] = []
                self._render(payload, prefix + cont, ancestors + [row])
            else:
                self.rows.append({'prefix': prefix + branch, 'name': name,
                                  'path': payload, 'is_dir': False})
                self.row_of[payload] = row
                for anc in ancestors:
                    self.dir_files[anc].append(payload)

    # ---- geometry ----------------------------------------------------------
    def fits(self):
        size = shutil.get_terminal_size((80, 24))
        return len(self.rows) + 2 <= size.lines and self.label_w + _MIN_ANNOT < size.columns * 2

    def _annot(self, path):
        state = self.status.get(path, 'pending')
        if state == 'pending':
            return _GLYPH_PENDING
        if state == 'scanning':
            return _GLYPH_SCANNING
        findings = self.results.get(path, [])
        if not findings:
            return _GLYPH_CLEAN
        sev = _worst(findings)
        return _SEVERITY_COLOR[sev] + ('✗ %d' % len(findings)) + end

    def _dir_annot(self, row):
        total = sum(len(self.results.get(p, [])) for p in self.dir_files.get(row, []))
        if not total:
            return ''
        worst = None
        for p in self.dir_files.get(row, []):
            sev = _worst(self.results.get(p, []))
            if sev is not None:
                rank = _SEVERITY_ORDER.index(sev)
                worst = rank if worst is None else min(worst, rank)
        color = _SEVERITY_COLOR[_SEVERITY_ORDER[worst]] if worst is not None else red
        return color + ('✗ %d' % total) + end

    def _line(self, row):
        entry = self.rows[row]
        label = entry['prefix'] + entry['name']
        cols = shutil.get_terminal_size((80, 24)).columns
        name_col = min(self.label_w, max(10, cols - _MIN_ANNOT))
        if len(label) > name_col:
            label = label[:name_col - 1] + '…'
        else:
            label = label.ljust(name_col)
        annot = self._dir_annot(row) if entry['is_dir'] else self._annot(entry['path'])
        return ('%s  %s' % (label, annot)).rstrip()

    # ---- rendering / updates ----------------------------------------------
    def render(self):
        sys.stdout.write('\n'.join(self._line(r) for r in range(len(self.rows))))
        sys.stdout.write('\n')
        sys.stdout.flush()
        self._rendered = True

    def _rewrite(self, row):
        if not self._rendered:
            return
        up = len(self.rows) - row
        sys.stdout.write('\033[%dA\r\033[K%s\r\033[%dB' % (up, self._line(row), up))
        sys.stdout.flush()

    def mark_scanning(self, path):
        path = os.path.abspath(path)
        if path in self.row_of:
            self.status[path] = 'scanning'
            self._rewrite(self.row_of[path])

    def mark_done(self, path, findings):
        path = os.path.abspath(path)
        if path in self.row_of:
            self.status[path] = 'done'
            self.results[path] = list(findings)
            self._rewrite(self.row_of[path])

    def finish(self):
        """Roll finding totals up onto the directory rows."""
        for row, entry in enumerate(self.rows):
            if entry['is_dir']:
                self._rewrite(row)
