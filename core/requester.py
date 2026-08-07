import http.client
import json as _json
import random
import socket
import ssl
import time
import urllib.error
import urllib.request
import warnings
from urllib.parse import urlencode

import core.config
from core.utils import converter, getVar
from core.log import setup_logger

logger = setup_logger(__name__)

warnings.filterwarnings('ignore')  # Disable SSL related warnings

# Accept self-signed / invalid certificates, mirroring requests' ``verify=False``.
_ssl_context = ssl.create_default_context()
_ssl_context.check_hostname = False
_ssl_context.verify_mode = ssl.CERT_NONE


class Response:
    """Minimal stand-in for ``requests.Response``.

    Only the attributes XSStrike actually reads are provided: ``text``,
    ``status_code`` and ``headers`` (a plain, JSON-serialisable dict).
    """

    def __init__(self, text='', status_code=None, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = dict(headers or {})


def _build_opener():
    proxies = core.config.proxies
    # An empty proxies dict means "no proxy" and also disables environment proxies.
    proxy_handler = urllib.request.ProxyHandler(proxies if proxies else {})
    https_handler = urllib.request.HTTPSHandler(context=_ssl_context)
    return urllib.request.build_opener(proxy_handler, https_handler)


def _to_response(raw):
    body = raw.read()
    charset = raw.headers.get_content_charset() or 'utf-8'
    return Response(text=body.decode(charset, errors='replace'),
                    status_code=raw.getcode(),
                    headers=dict(raw.headers.items()))


def _waf_drop():
    logger.warning('WAF is dropping suspicious requests.')
    logger.warning('Scanning will continue after 10 minutes.')
    time.sleep(600)
    return Response()


def requester(url, data, headers, GET, delay, timeout):
    if getVar('jsonData'):
        data = converter(data)
    elif getVar('path'):
        url = converter(data, url)
        data = []
        GET, POST = True, False
    time.sleep(delay)
    user_agents = ['Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0',
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
                   'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991']
    if 'User-Agent' not in headers:
        headers['User-Agent'] = random.choice(user_agents)
    elif headers['User-Agent'] == '$':
        headers['User-Agent'] = random.choice(user_agents)
    logger.debug('Requester url: {}'.format(url))
    logger.debug('Requester GET: {}'.format(GET))
    logger.debug_json('Requester data:', data)
    logger.debug_json('Requester headers:', headers)
    try:
        if GET:
            query = urlencode(data, doseq=True) if data else ''
            if query:
                url = url + ('&' if '?' in url else '?') + query
            request = urllib.request.Request(url, headers=headers, method='GET')
        elif getVar('jsonData'):
            body = _json.dumps(data).encode('utf-8')
            headers = dict(headers)
            headers.setdefault('Content-Type', 'application/json')
            request = urllib.request.Request(
                url, data=body, headers=headers, method='POST')
        else:
            body = urlencode(data, doseq=True).encode('utf-8')
            request = urllib.request.Request(
                url, data=body, headers=headers, method='POST')
        opener = _build_opener()
        return _to_response(opener.open(request, timeout=timeout))
    except urllib.error.HTTPError as e:
        # Unlike requests, urllib raises on 4xx/5xx; XSStrike needs those
        # responses (WAF detection, status checks), so surface them as-is.
        try:
            charset = e.headers.get_content_charset() or 'utf-8'
            text = e.read().decode(charset, errors='replace')
            resp_headers = dict(e.headers.items())
        except Exception:
            text, resp_headers = '', {}
        return Response(text=text, status_code=e.code, headers=resp_headers)
    except (ConnectionResetError, http.client.RemoteDisconnected):
        return _waf_drop()
    except urllib.error.URLError as e:
        if isinstance(e.reason, (ConnectionResetError, http.client.RemoteDisconnected)):
            return _waf_drop()
        logger.warning('Unable to connect to the target.')
        return Response()
    except (socket.timeout, http.client.HTTPException):
        logger.warning('Unable to connect to the target.')
        return Response()
    except Exception:
        logger.warning('Unable to connect to the target.')
        return Response()
