import copy
import re
from urllib.parse import urlparse, quote, unquote

from core.checker import checker
from core.colors import end, green, que, good, bad, info, yellow, red
import core.config
from core.config import xsschecker, minEfficiency
from core.dom import dom
from core.filterChecker import filterChecker
from core.generator import generator
from core.htmlParser import htmlParser
from core.requester import requester
from core.utils import getUrl, getParams, getVar
from core.wafDetector import wafDetector
from core.log import setup_logger

logger = setup_logger(__name__)


def scan(target, paramData, encoding, headers, delay, timeout, skipDOM, skip):
    GET, POST = (False, True) if paramData else (True, False)
    # If the user hasn't supplied the root url with http(s), we will handle it
    if not target.startswith('http'):
        try:
            response = requester('https://' + target, {},
                                 headers, GET, delay, timeout)
            target = 'https://' + target
        except:
            target = 'http://' + target
    logger.debug('Scan target: {}'.format(target))
    response = requester(target, {}, headers, GET, delay, timeout).text

    if not skipDOM:
        logger.run('Checking for DOM vulnerabilities')
        highlighted = dom(response)
        if highlighted:
            logger.good('Potentially vulnerable objects found')
            logger.red_line(level='good')
            for line in highlighted:
                logger.no_format(line, level='good')
            logger.red_line(level='good')
    host = urlparse(target).netloc  # Extracts host out of the url
    logger.debug('Host to scan: {}'.format(host))
    url = getUrl(target, GET)
    logger.debug('Url to scan: {}'.format(url))
    params = getParams(target, paramData, GET)
    logger.debug_json('Scan parameters:', params)
    if not params:
        logger.error('No parameters to test.')
        quit()
    WAF = wafDetector(
        url, {list(params.keys())[0]: xsschecker}, headers, GET, delay, timeout)
    if WAF:
        logger.error('WAF detected: %s%s%s' % (green, WAF, end))
    else:
        logger.good('WAF Status: %sOffline%s' % (green, end))

    # Stats collected across every tested parameter for the closing summary panel
    reflectionsTotal = 0
    payloadsTotal = 0
    vulnCount = 0

    for paramName in params.keys():
        paramsCopy = copy.deepcopy(params)
        logger.info('Testing parameter: %s' % paramName)
        if encoding:
            paramsCopy[paramName] = encoding(xsschecker)
        else:
            paramsCopy[paramName] = xsschecker
        response = requester(url, paramsCopy, headers, GET, delay, timeout)
        occurences = htmlParser(response, encoding)
        positions = occurences.keys()
        logger.debug('Scan occurences: {}'.format(occurences))
        if not occurences:
            logger.error('No reflection found')
            continue
        else:
            logger.info('Reflections found: %i' % len(occurences))
            reflectionsTotal += len(occurences)

        logger.run('Analysing reflections')
        efficiencies = filterChecker(
            url, paramsCopy, headers, GET, delay, occurences, timeout, encoding)
        logger.debug('Scan efficiencies: {}'.format(efficiencies))
        logger.run('Generating payloads')
        vectors = generator(occurences, response.text)
        total = 0
        for v in vectors.values():
            total += len(v)
        if total == 0:
            logger.error('No vectors were crafted.')
            continue
        logger.info('Payloads generated: %i' % total)
        payloadsTotal += total
        progress = 0
        for confidence, vects in vectors.items():
            for vect in vects:
                if core.config.globalVariables['path']:
                    vect = vect.replace('/', '%2F')
                loggerVector = vect
                progress += 1
                logger.run('Progress: %i/%i\r' % (progress, total))
                if not GET:
                    vect = unquote(vect)
                efficiencies = checker(
                    url, paramsCopy, headers, GET, delay, vect, positions, timeout, encoding)
                if not efficiencies:
                    for i in range(len(occurences)):
                        efficiencies.append(0)
                bestEfficiency = max(efficiencies)
                if bestEfficiency == 100 or (vect[0] == '\\' and bestEfficiency >= 95):
                    vulnCount += 1
                    logger.red_line()
                    logger.good('Payload: %s' % loggerVector)
                    logger.info('Efficiency: %i' % bestEfficiency)
                    logger.info('Confidence: %i' % confidence)
                    if not skip:
                        choice = input(
                            '%s Would you like to continue scanning? [y/N] ' % que).lower()
                        if choice != 'y':
                            quit()
                elif bestEfficiency > minEfficiency:
                    vulnCount += 1
                    logger.red_line()
                    logger.good('Payload: %s' % loggerVector)
                    logger.info('Efficiency: %i' % bestEfficiency)
                    logger.info('Confidence: %i' % confidence)
        logger.no_format('')

    # Closing DOS-style summary panel
    wafLabel = ('%s%s%s' % (yellow, WAF, end)) if WAF else ('%sOffline%s' % (green, end))
    vulnColor = red if vulnCount else green
    frameColor = red if vulnCount else green
    label = '{:<11}'.format
    summary = [
        '%s %s: %s' % (info, label('Target'), url),
        '%s %s: %s' % (good if not WAF else bad, label('WAF'), wafLabel),
        '%s %s: %i' % (info, label('Parameters'), len(params)),
        '%s %s: %i' % (info, label('Reflections'), reflectionsTotal),
        '%s %s: %i' % (info, label('Payloads'), payloadsTotal),
        '%s %s: %s%i%s' % (
            good if vulnCount else info, label('Vulnerable'),
            vulnColor, vulnCount, end),
    ]
    logger.box(summary, title='Scan Summary',
               level='good' if vulnCount else 'info', color=frameColor)
