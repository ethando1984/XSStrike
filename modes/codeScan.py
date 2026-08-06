#!/usr/bin/env python3

import os
import json
import core.log

from core.colors import green, red, yellow, end
from core.staticScanner import scanDirectory

logger = core.log.setup_logger(__name__)

SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

SEVERITY_COLOR = {
    'CRITICAL': red,
    'HIGH': red,
    'MEDIUM': yellow,
    'LOW': green,
}


def codeScan(path, output=None, min_severity='LOW', include_unknown=False, limit=0):
    """Scan a source directory for security issues and report them."""
    if not os.path.isdir(path):
        logger.error('Not a directory: %s' % path)
        return 2

    path = os.path.abspath(path)
    logger.run('Scanning source directory: %s' % path)

    def progress(scanned, found):
        logger.info('Scanned %i files, %i findings\r' % (scanned, found))

    extra_ignore = []
    if output:  # never scan the report we are about to write
        out_abs = os.path.abspath(output)
        if out_abs.startswith(path + os.sep):
            extra_ignore.append(os.path.relpath(out_abs, path))

    findings, scanned = scanDirectory(
        path, include_unknown=include_unknown, progress=progress,
        extra_ignore=extra_ignore)
    logger.no_format('')

    cutoff = SEVERITY_ORDER.index(min_severity.upper()) \
        if min_severity.upper() in SEVERITY_ORDER else len(SEVERITY_ORDER) - 1
    findings = [f for f in findings
                if SEVERITY_ORDER.index(f.severity) <= cutoff]

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.path, f.line_no))

    counts = {level: 0 for level in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1

    logger.info('Files scanned: %i' % scanned)
    if not findings:
        logger.good('No security issues found.')
    else:
        logger.red_line()
        for level in SEVERITY_ORDER:
            if counts[level]:
                logger.no_format('%s%s%s: %i' % (
                    SEVERITY_COLOR[level], level, end, counts[level]))
        logger.red_line()

        shown = findings[:limit] if limit else findings
        for finding in shown:
            colour = SEVERITY_COLOR[finding.severity]
            rel = os.path.relpath(finding.path, path)
            logger.no_format('%s[%s]%s %s (%s)' % (
                colour, finding.severity, end, finding.name, finding.cwe))
            logger.no_format('    %s:%i' % (rel, finding.line_no))
            logger.no_format('    %s' % finding.snippet)
            logger.no_format('    %s' % finding.desc)
            logger.no_format('')
        if limit and len(findings) > limit:
            logger.info('%i more findings not shown, use --json-out for the full list'
                        % (len(findings) - limit))

    if output:
        report = dict(
            target=path,
            files_scanned=scanned,
            total_findings=len(findings),
            summary=counts,
            findings=[f.as_dict() for f in findings],
        )
        try:
            with open(output, 'w', encoding='utf-8') as handle:
                json.dump(report, handle, indent=2)
            logger.good('JSON report written to %s' % output)
        except (IOError, OSError) as error:
            logger.error('Could not write report: %s' % error)

    if counts['CRITICAL'] or counts['HIGH']:
        return 1
    return 0
