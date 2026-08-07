import re
import sys
import concurrent.futures
from urllib.parse import urlparse

from core.dom import dom
from core.log import setup_logger
from core.utils import getUrl, getParams, extractLinks
from core.requester import requester
from core.zetanize import zetanize
from core import headlessCrawler
from plugins.retireJs import retireJs

logger = setup_logger(__name__)


def photon(seedUrl, headers, level, threadCount, delay, timeout, skipDOM, headless=False):
    if headless:
        # Only nag about a missing Playwright when the user actually asked for
        # headless; when it is just the default-on setting, degrade quietly.
        explicit = '--headless' in sys.argv
        if headlessCrawler.is_available(warn=explicit):
            logger.info('Headless rendering enabled (crawling single-threaded)')
            threadCount = 1
        else:
            headless = False
    forms = []  # web forms
    processed = set()  # urls that have been crawled
    storage = set()  # urls that belong to the target i.e. in-scope
    schema = urlparse(seedUrl).scheme  # extract the scheme e.g. http or https
    host = urlparse(seedUrl).netloc  # extract the host e.g. example.com
    main_url = schema + '://' + host  # join scheme and host to make the root url
    storage.add(seedUrl)  # add the url to storage
    checkedDOMs = []

    def rec(target):
        processed.add(target)
        printableTarget = '/'.join(target.split('/')[3:])
        if len(printableTarget) > 40:
            printableTarget = printableTarget[-40:]
        else:
            printableTarget = (printableTarget + (' ' * (40 - len(printableTarget))))
        logger.run('Parsing %s\r' % printableTarget)
        url = getUrl(target, True)
        params = getParams(target, '', True)
        if '=' in target:  # if there's a = in the url, there should be GET parameters
            inps = []
            for name, value in params.items():
                inps.append({'name': name, 'value': value})
            forms.append({0: {'action': url, 'method': 'get', 'inputs': inps}})
        response = None
        if headless:
            # render the full URL (with query string) so JS runs against it
            response = headlessCrawler.render(target, headers, timeout)
        if response is None:  # not headless, or the render failed -> plain HTTP
            response = requester(url, params, headers, True, delay, timeout).text
        retireJs(url, response)
        if not skipDOM:
            highlighted = dom(response)
            clean_highlighted = ''.join([re.sub(r'^\d+\s+', '', line) for line in highlighted])
            if highlighted and clean_highlighted not in checkedDOMs:
                checkedDOMs.append(clean_highlighted)
                logger.good('Potentially vulnerable objects found at %s' % url)
                logger.red_line(level='good')
                for line in highlighted:
                    logger.no_format(line, level='good')
                logger.red_line(level='good')
        forms.append(zetanize(response))
        # scrape in-scope links, including parameterised URLs and API
        # endpoints embedded in inline scripts / JSON (SPA-friendly)
        for link in extractLinks(response, schema, host, main_url):
            storage.add(link)
            # a URL with GET parameters is directly XSS-testable, so
            # register it as a form even if it wasn't the crawl seed
            if '?' in link and '=' in link:
                inps = []
                for name, value in (getParams(link, '', True) or {}).items():
                    inps.append({'name': name, 'value': value})
                if inps:
                    forms.append(
                        {0: {'action': getUrl(link, True),
                             'method': 'get', 'inputs': inps}})
    try:
        for x in range(level):
            urls = storage - processed  # urls to crawl = all urls - urls that have been crawled
            # for url in urls:
            #     rec(url)
            threadpool = concurrent.futures.ThreadPoolExecutor(
                max_workers=threadCount)
            futures = (threadpool.submit(rec, url) for url in urls)
            for i in concurrent.futures.as_completed(futures):
                pass
    except KeyboardInterrupt:
        return [forms, processed]
    return [forms, processed]
