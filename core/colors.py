import re
import sys
import os
import platform

# --- Color support detection -------------------------------------------------
# Colors are enabled when writing to a real terminal, unless the user opts out
# via the NO_COLOR convention (https://no-color.org/). On modern Windows we
# also flip on ANSI escape processing.
colors = True
machine = sys.platform  # Detecting the os of current system
checkplatform = platform.platform()  # Get current version of OS

if os.environ.get('NO_COLOR') is not None or os.environ.get('TERM') == 'dumb':
    colors = False
elif not (hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()):
    # Piped/redirected output: keep it clean, no escape codes.
    colors = False
elif machine.lower().startswith('win'):
    colors = False
    try:
        # Windows 10 build 10586+ understands ANSI once we poke the console.
        if checkplatform.startswith('Windows-10') and int(platform.version().split('.')[2]) >= 10586:
            colors = True
            os.system('')  # Enables the ANSI escape sequences
    except (IndexError, ValueError):
        colors = False

if not colors:
    end = red = white = green = yellow = run = bad = good = info = que = back = grey = ''
else:
    white = '\033[97m'
    green = '\033[92m'
    red = '\033[91m'
    yellow = '\033[93m'
    grey = '\033[90m'
    end = '\033[0m'
    back = '\033[7;91m'
    info = '\033[93m[!]\033[0m'
    que = '\033[94m[?]\033[0m'
    bad = '\033[91m[-]\033[0m'
    good = '\033[92m[+]\033[0m'
    run = '\033[97m[~]\033[0m'

# --- DOS-style box drawing ---------------------------------------------------
# Double-line frame characters, the classic BIOS/DOS terminal look.
box_tl, box_tr, box_bl, box_br = '╔', '╗', '╚', '╝'
box_h, box_v = '═', '║'
box_ml, box_mr = '╠', '╣'

_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def visible_len(text):
    """Length of a string ignoring ANSI color escape sequences."""
    return len(_ANSI_RE.sub('', text))


def draw_box(lines, title=None, width=None, color=red, pad=1):
    """Render a DOS-style boxed panel and return it as a single string.

    ``lines`` is a list of already-formatted (optionally colored) content rows.
    ``title`` is centered in a header separated by a mid-rule. ``width`` forces
    a minimum inner content width; otherwise the box hugs its content.
    """
    frame = color
    reset = end if color else ''
    body = list(lines)

    inner = max([visible_len(line) for line in body] or [0])
    if title is not None:
        inner = max(inner, visible_len(title))
    if width:
        inner = max(inner, width)

    span = inner + pad * 2  # horizontal run between the corners
    gap = ' ' * pad

    def border(left, right):
        return '{f}{l}{h}{r}{e}'.format(
            f=frame, l=left, h=box_h * span, r=right, e=reset)

    def content_row(text, center=False):
        free = inner - visible_len(text)
        if center:
            left = free // 2
            filled = (' ' * left) + text + (' ' * (free - left))
        else:
            filled = text + (' ' * free)
        return '{f}{v}{e}{g}{t}{g}{f}{v}{e}'.format(
            f=frame, v=box_v, e=reset, g=gap, t=filled)

    out = [border(box_tl, box_tr)]
    if title is not None:
        out.append(content_row(title, center=True))
        out.append(border(box_ml, box_mr))
    for line in body:
        out.append(content_row(line))
    out.append(border(box_bl, box_br))
    return '\n'.join(out)


def banner(version='v3.2.0'):
    """The XSStrike splash banner, framed DOS-style."""
    title = '{w}XSStrike {r}{v}{e}'.format(w=white, r=red, v=version, e=end)
    subtitle = '{g}Advanced XSS Detection Suite{e}'.format(g=grey, e=end)
    return '{r}{box}{e}'.format(
        r=red,
        box=draw_box([subtitle], title=title, width=34, color=red),
        e=end)
