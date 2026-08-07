import os
import re
from urllib.request import Request, urlopen

from core.config import changes
from core.colors import que, info, end, green
from core.log import setup_logger

logger = setup_logger(__name__)


def updater():
    logger.run('Checking for updates')
    try:
        request = Request(
            'https://raw.githubusercontent.com/ethando1984/XSStrike/master/core/config.py',
            headers={'User-Agent': 'XSStrike'})
        with urlopen(request, timeout=10) as response:
            latestCommit = response.read().decode('utf-8', errors='replace')
    except Exception:
        logger.error('Unable to check for updates.')
        return

    if changes not in latestCommit:  # just a hack to see if a new version is available
        changelog = re.search(r"changes = '''(.*?)'''", latestCommit)
        changelog = changelog.group(1).split(
            ';')  # splitting the changes to form a list
        logger.good('A new version of XSStrike is available.')
        changes_str = 'Changes:\n'
        for change in changelog:  # prepare changes to print
            changes_str += '%s>%s %s\n' % (green, end, change)
        logger.info(changes_str)
        currentPath = os.getcwd().split('/')  # if you know it, you know it
        folder = currentPath[-1]  # current directory name
        path = '/'.join(currentPath)  # current directory path
        choice = input('%s Would you like to update? [Y/n] ' % que).lower()

        if choice != 'n':
            logger.run('Updating XSStrike')
            os.system(
                'git clone --quiet https://github.com/ethando1984/XSStrike %s' % (folder))
            os.system('cp -r %s/%s/* %s && rm -r %s/%s/ 2>/dev/null' %
                      (path, folder, path, path, folder))
            logger.good('Update successful!')
    else:
        logger.good('XSStrike is up to date!')
