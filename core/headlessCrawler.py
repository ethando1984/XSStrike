import atexit

from core.log import setup_logger

logger = setup_logger(__name__)

# Lazily-initialised singletons so we pay the browser start-up cost once.
_playwright = None
_browser = None
_available = None  # None = unknown, True/False once probed


def is_available():
    """Return True if Playwright and a browser binary are usable."""
    global _available
    if _available is not None:
        return _available
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        _available = True
    except ImportError:
        logger.error(
            'Headless mode needs Playwright. Install with: '
            'pip install playwright && playwright install chromium')
        _available = False
    return _available


def _get_browser():
    global _playwright, _browser
    if _browser is not None:
        return _browser
    from playwright.sync_api import sync_playwright
    _playwright = sync_playwright().start()
    _browser = _playwright.chromium.launch(headless=True)
    atexit.register(shutdown)
    return _browser


def render(url, headers, timeout):
    """Load ``url`` in a headless browser and return the rendered HTML.

    Returns the post-JavaScript DOM as a string, or None on failure so the
    caller can fall back to a plain HTTP request. ``timeout`` is in seconds
    (matching the rest of XSStrike); Playwright expects milliseconds.
    """
    if not is_available():
        return None
    context = None
    try:
        browser = _get_browser()
        context = browser.new_context(
            extra_http_headers={k: str(v) for k, v in (headers or {}).items()},
            ignore_https_errors=True)
        page = context.new_page()
        # 'networkidle' rarely settles on ad/tracker-heavy sites, so wait for
        # the DOM then give client-side JS a brief moment to populate content.
        page.goto(url, wait_until='domcontentloaded',
                  timeout=max(1, int(timeout)) * 1000)
        try:
            page.wait_for_load_state('networkidle', timeout=3000)
        except Exception:
            page.wait_for_timeout(2000)  # best-effort settle for SPA rendering
        html = page.content()
        return html
    except Exception as e:
        logger.debug('Headless render failed for %s: %s' % (url, e))
        return None
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass


def shutdown():
    global _playwright, _browser
    if _browser is not None:
        try:
            _browser.close()
        except Exception:
            pass
        _browser = None
    if _playwright is not None:
        try:
            _playwright.stop()
        except Exception:
            pass
        _playwright = None
