import atexit

from core.log import setup_logger

logger = setup_logger(__name__)

# Lazily-initialised singletons so we pay the browser start-up cost once.
_playwright = None
_browser = None
_available = None  # None = unknown, True/False once probed


def is_available(warn=False):
    """Return True if the Playwright package is importable.

    This only probes the Python package; a missing *browser binary* surfaces
    later in :func:`_get_browser`. ``warn`` controls whether an unmet dependency
    is announced: pass ``True`` only when headless was *explicitly* requested, so
    that the default-on crawl doesn't nag users who never asked for it.
    """
    global _available
    if _available is not None:
        return _available
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        _available = True
    except ImportError:
        if warn:
            logger.warning(
                'Headless mode needs Playwright; falling back to plain HTTP '
                'crawling. Install with: pip install playwright && '
                'playwright install chromium')
        else:
            logger.debug('Playwright not installed; crawling with plain HTTP.')
        _available = False
    return _available


def _get_browser():
    global _playwright, _browser, _available
    if _browser is not None:
        return _browser
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    try:
        _browser = pw.chromium.launch(headless=True)
    except Exception as exc:
        # The package imports but the browser binary is missing/unlaunchable.
        # Stop the driver we just started (else it leaks) and mark headless
        # unavailable so is_available() short-circuits every later URL instead
        # of restarting a driver and failing to launch again and again.
        try:
            pw.stop()
        except Exception:
            pass
        _available = False
        logger.warning('Headless browser could not launch (%s); falling back '
                       'to plain HTTP. Run: playwright install chromium' % exc)
        raise
    _playwright = pw
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
