#!/usr/bin/env python3
"""Static (source code) vulnerability scanner used by the --scan-dir mode.

Self-contained pattern based engine, no third party dependency. Rules are
tagged with the languages they apply to so a file is only matched against
rules that make sense for it.
"""

import os
import re
import fnmatch

# extension -> language id
EXTENSIONS = {
    '.py': 'python',
    '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
    '.ts': 'typescript', '.tsx': 'typescript',
    '.php': 'php', '.phtml': 'php',
    '.java': 'java',
    '.go': 'go',
    '.rb': 'ruby', '.erb': 'ruby',
    '.cs': 'csharp',
    '.c': 'c', '.h': 'c', '.cpp': 'cpp', '.cc': 'cpp', '.hpp': 'cpp',
    '.html': 'html', '.htm': 'html',
    '.jsp': 'java',
    '.sh': 'shell', '.bash': 'shell',
    '.yml': 'config', '.yaml': 'config', '.json': 'config',
    '.tf': 'terraform',
    '.sql': 'sql',
    '.kt': 'kotlin', '.kts': 'kotlin',
    '.swift': 'swift',
    '.scala': 'scala',
    '.rs': 'rust',
    '.pl': 'perl', '.pm': 'perl',
    '.lua': 'lua',
    '.vue': 'javascript', '.svelte': 'javascript',
    '.env': 'config', '.ini': 'config', '.cfg': 'config', '.conf': 'config',
    '.properties': 'config', '.toml': 'config', '.xml': 'config',
    '.pem': 'secret', '.key': 'secret', '.p12': 'secret', '.pfx': 'secret',
}

# files without a useful extension that are still worth scanning
FILENAMES = {
    'dockerfile': 'docker',
    'makefile': 'shell',
    '.env': 'config',
    '.npmrc': 'config',
    '.netrc': 'config',
    'id_rsa': 'secret',
    'id_dsa': 'secret',
}

SKIP_DIRS = {
    '.git', '.svn', '.hg', 'node_modules', 'vendor', 'venv', '.venv', 'env',
    '__pycache__', 'dist', 'build', 'target', '.idea', '.vscode', '.tox',
    'site-packages', 'bower_components', '.mypy_cache', '.pytest_cache',
    'coverage', '.next', '.nuxt', '.codescan',
}

SKIP_FILE_RE = re.compile(r'(\.min\.js|\.min\.css|\.map|-lock\.json|\.lock)$', re.I)

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB
ANY = '*'

# Each rule: id, name, severity, cwe, langs, regex, description
RULES = [
    # ---------------- Cross Site Scripting ----------------
    dict(id='xss-innerhtml', name='DOM XSS via innerHTML', severity='HIGH', cwe='CWE-79',
         langs=['javascript', 'typescript', 'html'],
         regex=r'\.(innerHTML|outerHTML)\s*=\s*(?!["\'`]\s*["\'`])[^;\n]*(?:\+|\$\{|`)',
         desc='Untrusted data assigned to innerHTML/outerHTML is rendered as HTML.'),
    dict(id='xss-document-write', name='DOM XSS via document.write', severity='HIGH', cwe='CWE-79',
         langs=['javascript', 'typescript', 'html'],
         regex=r'document\.(write|writeln)\s*\([^)]*(?:\+|\$\{|location|document\.URL|search|hash)',
         desc='document.write with dynamic input allows script injection.'),
    dict(id='xss-jquery-html', name='DOM XSS via jQuery .html()', severity='MEDIUM', cwe='CWE-79',
         langs=['javascript', 'typescript'],
         regex=r'\$\([^)]*\)\.(html|append|prepend|after|before)\s*\([^)]*(?:\+|\$\{|location|param)',
         desc='jQuery HTML insertion sinks execute embedded scripts.'),
    dict(id='xss-php-echo', name='Reflected XSS in PHP output', severity='HIGH', cwe='CWE-79',
         langs=['php'],
         regex=r'(?:echo|print)\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)\b',
         desc='Request data echoed without htmlspecialchars() encoding.'),
    dict(id='xss-react-dangerous', name='React dangerouslySetInnerHTML', severity='MEDIUM', cwe='CWE-79',
         langs=['javascript', 'typescript'],
         regex=r'dangerouslySetInnerHTML',
         desc='Bypasses React escaping; verify the value is sanitized.'),
    dict(id='xss-template-autoescape-off', name='Template auto-escaping disabled', severity='HIGH', cwe='CWE-79',
         langs=[ANY],
         regex=r'(autoescape\s*=\s*False|\|\s*safe\b|\{\{-?\s*\w+\s*\|\s*raw\s*\}\}|MarkupSafe\s*\(\s*)',
         desc='Output escaping turned off, HTML injection becomes possible.'),

    # ---------------- Injection ----------------
    dict(id='sqli-concat', name='SQL injection via string building', severity='CRITICAL', cwe='CWE-89',
         langs=[ANY],
         regex=r'(?i)(?:execute|executemany|query|rawQuery|prepare|createStatement\(\)\.execute\w*)\s*\(\s*[^)]*?["\'](?:\s*SELECT|\s*INSERT|\s*UPDATE|\s*DELETE)[^)]*?(?:\+|%s?\s*%|\$\{|\.format\(|f["\'])',
         desc='SQL built by concatenation/interpolation. Use parameterised queries.'),
    dict(id='sqli-fstring', name='SQL injection via f-string', severity='CRITICAL', cwe='CWE-89',
         langs=['python'],
         regex=r'(?i)f["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"\']*\{',
         desc='f-string interpolation inside an SQL statement.'),
    dict(id='cmdi-shell-true', name='Command injection (shell=True)', severity='CRITICAL', cwe='CWE-78',
         langs=['python'],
         regex=r'subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True',
         desc='shell=True with dynamic input allows arbitrary command execution.'),
    dict(id='cmdi-os-system', name='Command injection via os.system', severity='HIGH', cwe='CWE-78',
         langs=['python'],
         regex=r'os\.(?:system|popen)\s*\(\s*(?![\'"][^\'"]*[\'"]\s*\))'
               r'[^)]*(?:\+|%|\.format\b|f[\'"]|\bformat_map\b|[A-Za-z_]\w*\s*[,)])',
         desc='os.system/os.popen with dynamic input passes it to a shell.'),
    dict(id='cmdi-exec', name='Command execution sink', severity='HIGH', cwe='CWE-78',
         langs=['javascript', 'typescript', 'php', 'ruby', 'go', 'java'],
         regex=r'(?:child_process\.exec|exec_r?\s*\(|\bsystem\s*\(|\bshell_exec\s*\(|\bpassthru\s*\(|`[^`]*\$\{|Runtime\.getRuntime\(\)\.exec|os/exec\.Command)',
         desc='Shell command built at runtime; validate or avoid shell invocation.'),
    dict(id='code-eval', name='Dynamic code evaluation', severity='HIGH', cwe='CWE-95',
         langs=[ANY],
         regex=r'(?<![\w.])(?:eval|exec)\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*["\']|assert\s*\(\s*\$|create_function\s*\(',
         desc='eval-style execution of dynamic strings enables code injection.'),
    dict(id='ldapi-xpath', name='LDAP/XPath injection', severity='HIGH', cwe='CWE-90',
         langs=[ANY],
         regex=r'(?i)(?:search_s?|ldap_search|selectNodes|evaluate|compile)\s*\([^)]*(?:\+\s*\w+|\$\{|\.format\()[^)]*(?:uid=|cn=|//\*)',
         desc='LDAP/XPath filter built from unvalidated input.'),
    dict(id='ssti', name='Server side template injection', severity='HIGH', cwe='CWE-1336',
         langs=[ANY],
         regex=r'(?:render_template_string|Template\s*\(\s*(?:request|params|input|user)|from_string\s*\()',
         desc='Template compiled from user controlled string.'),
    dict(id='nosqli', name='NoSQL injection ($where / where)', severity='HIGH', cwe='CWE-943',
         langs=[ANY],
         regex=r'(?:\$where["\']?\s*:|\.where\s*\(\s*["\'][^"\']*\+)',
         desc='NoSQL query built from raw input.'),

    # ---------------- Deserialization / file ----------------
    dict(id='insecure-deser', name='Insecure deserialization', severity='CRITICAL', cwe='CWE-502',
         langs=[ANY],
         regex=r'(?:pickle\.loads?|cPickle\.loads?|yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)|marshal\.loads|unserialize\s*\(|ObjectInputStream|readObject\s*\(|JsonConvert\.DeserializeObject<[^>]*>\s*\([^)]*TypeNameHandling)',
         desc='Deserializing untrusted data can lead to remote code execution.'),
    dict(id='path-traversal', name='Path traversal', severity='HIGH', cwe='CWE-22',
         langs=[ANY],
         regex=r'(?:open|readFile|readFileSync|file_get_contents|File\s*\(|sendFile|include|require_once|fopen)\s*\([^)]*(?:\+\s*(?:req|request|params|input|user|argv)|\$_(?:GET|POST|REQUEST)|\$\{\s*(?:req|params))',
         desc='File path built from user input without normalisation.'),
    dict(id='zip-slip', name='Zip slip / archive extraction', severity='MEDIUM', cwe='CWE-22',
         langs=[ANY],
         regex=r'(?:extractall\s*\(|ZipEntry\.getName\s*\(|tarfile\.open)',
         desc='Archive entries may contain ../ paths; validate before extracting.'),
    dict(id='xxe', name='XML external entity processing', severity='HIGH', cwe='CWE-611',
         langs=[ANY],
         regex=r'(?:etree\.parse|XMLParser\s*\(\s*(?![^)]*resolve_entities\s*=\s*False)|DocumentBuilderFactory|SAXParserFactory|libxml_disable_entity_loader\s*\(\s*false|XmlReaderSettings)',
         desc='XML parser may resolve external entities; disable DTD/entities.'),

    # ---------------- Crypto / secrets ----------------
    dict(id='weak-hash', name='Weak hash algorithm', severity='MEDIUM', cwe='CWE-327',
         langs=[ANY],
         regex=r'(?i)(?:hashlib\.(?:md5|sha1)|MD5\.Create|MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-?1)|createHash\s*\(\s*["\'](?:md5|sha1)|\bmd5\s*\(|\bsha1\s*\()',
         desc='MD5/SHA1 are not collision resistant; use SHA-256 or better.'),
    dict(id='weak-cipher', name='Weak or broken cipher', severity='HIGH', cwe='CWE-327',
         langs=[ANY],
         regex=r'(?i)(?:DES|RC4|Blowfish|ECB)(?:\.new|Cipher|["\']|_MODE)|Cipher\.getInstance\s*\(\s*["\'][^"\']*ECB',
         desc='Broken cipher or ECB mode leaks plaintext structure.'),
    dict(id='weak-random', name='Insecure randomness for security value', severity='MEDIUM', cwe='CWE-338',
         langs=[ANY],
         regex=r'(?i)(?:random\.(?:random|randint|choice)|Math\.random\s*\(|mt_rand\s*\(|new\s+Random\s*\()[^\n]*(?:token|secret|password|key|nonce|salt|otp|session)',
         desc='Non-cryptographic RNG used to generate a security sensitive value.'),
    dict(id='disabled-tls', name='TLS verification disabled', severity='HIGH', cwe='CWE-295',
         langs=[ANY],
         regex=r'(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false)|ServerCertificateValidationCallback)',
         desc='Certificate validation turned off, traffic can be intercepted.'),
    dict(id='hardcoded-secret', name='Hardcoded credential', severity='CRITICAL', cwe='CWE-798',
         langs=[ANY],
         regex=r'(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)\s*[:=]\s*["\'][^"\'\s$\{><]{8,}["\']',
         desc='Credential embedded in source; move it to a secret store.'),
    dict(id='secret-aws', name='AWS access key id', severity='CRITICAL', cwe='CWE-798',
         langs=[ANY], regex=r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b',
         desc='AWS access key committed to source.'),
    dict(id='secret-privatekey', name='Private key material', severity='CRITICAL', cwe='CWE-798',
         langs=[ANY], regex=r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY',
         desc='Private key stored in the repository.'),
    dict(id='secret-jwt', name='Hardcoded JWT', severity='HIGH', cwe='CWE-798',
         langs=[ANY], regex=r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.',
         desc='JSON Web Token embedded in source.'),
    dict(id='secret-slack-github', name='Provider token (Slack/GitHub/Stripe)', severity='CRITICAL', cwe='CWE-798',
         langs=[ANY], regex=r'\b(?:xox[abprs]-[A-Za-z0-9-]{10,}|gh[pousr]_[A-Za-z0-9]{30,}|sk_live_[A-Za-z0-9]{16,})\b',
         desc='Third party API token committed to source.'),

    # ---------------- Web / config ----------------
    dict(id='ssrf', name='Server side request forgery', severity='HIGH', cwe='CWE-918',
         langs=[ANY],
         regex=r'(?:requests\.(?:get|post|put|head)|urlopen|axios\.(?:get|post)|fetch|curl_setopt[^;]*CURLOPT_URL|HttpClient[^;]*Get)\s*\([^)]*(?:request\.(?:args|form|GET|POST|params)|\$_(?:GET|POST|REQUEST)|req\.(?:query|body|params))',
         desc='Outbound request to a user supplied URL; enforce an allowlist.'),
    dict(id='open-redirect', name='Open redirect', severity='MEDIUM', cwe='CWE-601',
         langs=[ANY],
         regex=r'(?:redirect|sendRedirect|Location["\']?\s*[,:]|header\s*\(\s*["\']Location)\s*[^;\n]*(?:request\.(?:args|GET|params)|\$_(?:GET|POST|REQUEST)|req\.(?:query|body))',
         desc='Redirect target taken from user input.'),
    dict(id='cors-wildcard', name='Permissive CORS policy', severity='MEDIUM', cwe='CWE-942',
         langs=[ANY],
         regex=r'(?i)Access-Control-Allow-Origin["\']?\s*[,:=]\s*["\']\*|origin\s*:\s*true.*credentials\s*:\s*true',
         desc='Wildcard origin (or origin+credentials) exposes authenticated data.'),
    dict(id='cookie-insecure', name='Cookie missing security flags', severity='MEDIUM', cwe='CWE-1004',
         langs=[ANY],
         regex=r'(?i)(?:set_cookie|setcookie|Cookie\s*\()[^;\n)]*(?:httponly\s*=\s*False|secure\s*=\s*False)',
         desc='Cookie set without HttpOnly/Secure, readable by scripts.'),
    dict(id='csrf-disabled', name='CSRF protection disabled', severity='HIGH', cwe='CWE-352',
         langs=[ANY],
         regex=r'(?i)(?:csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|csrf\s*:\s*false|ValidateAntiForgeryToken\s*=\s*false|\.csrf\(\)\.disable\(\))',
         desc='Cross site request forgery protection turned off.'),
    dict(id='debug-enabled', name='Debug mode enabled', severity='MEDIUM', cwe='CWE-489',
         langs=[ANY],
         regex=r'(?i)(?:DEBUG\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True|display_errors\s*=\s*On)',
         desc='Debug mode leaks stack traces and can expose a console.'),
    dict(id='bind-all-interfaces', name='Service bound to all interfaces', severity='LOW', cwe='CWE-668',
         langs=[ANY],
         regex=r'(?:0\.0\.0\.0|::)\s*["\']?\s*[,:]\s*\d{2,5}|host\s*=\s*["\']0\.0\.0\.0',
         desc='Listening on every interface may expose the service publicly.'),
    dict(id='sql-wildcard-perm', name='Overly broad SQL grant', severity='MEDIUM', cwe='CWE-732',
         langs=['sql'],
         regex=r'(?i)GRANT\s+ALL\s+PRIVILEGES\s+ON\s+\*',
         desc='Grants full privileges on every database.'),
]

COMMENT_RE = re.compile(r'^\s*(#(?!!)|//|\*|/\*|<!--|--\s)')


class Finding(object):
    def __init__(self, rule, path, line_no, line):
        self.rule_id = rule['id']
        self.name = rule['name']
        self.severity = rule['severity']
        self.cwe = rule['cwe']
        self.desc = rule['desc']
        self.path = path
        self.line_no = line_no
        self.snippet = line.strip()[:200]

    def as_dict(self):
        return dict(rule_id=self.rule_id, name=self.name, severity=self.severity,
                    cwe=self.cwe, description=self.desc, path=self.path,
                    line=self.line_no, snippet=self.snippet)


def _compile(rules):
    compiled = []
    for rule in rules:
        try:
            compiled.append((rule, re.compile(rule['regex'])))
        except re.error:
            continue
    return compiled


COMPILED = _compile(RULES)


def detectLanguage(path):
    name = os.path.basename(path).lower()
    if name in FILENAMES:
        return FILENAMES[name]
    if name.startswith('dockerfile'):
        return 'docker'
    return EXTENSIONS.get(os.path.splitext(path)[1].lower())


SELF_PATH = os.path.abspath(__file__)


def loadIgnorePatterns(root):
    """Read .xsstrikeignore (one glob per line) from the scan root."""
    patterns = []
    ignore_file = os.path.join(root, '.xsstrikeignore')
    try:
        with open(ignore_file, 'r', encoding='utf-8', errors='ignore') as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith('#'):
                    patterns.append(line)
    except (IOError, OSError):
        pass
    return patterns


def collectFiles(root, include_unknown=False, ignore=None):
    """Walk root and yield (path, language) for scannable source files."""
    ignore = ignore if ignore is not None else loadIgnorePatterns(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith('.')]
        for name in filenames:
            if SKIP_FILE_RE.search(name):
                continue
            full = os.path.join(dirpath, name)
            if os.path.abspath(full) == SELF_PATH:
                continue  # the rule definitions match themselves
            rel = os.path.relpath(full, root)
            if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(name, pat)
                   for pat in ignore):
                continue
            lang = detectLanguage(full)
            if lang is None and not include_unknown:
                continue
            try:
                if os.path.getsize(full) > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            yield full, (lang or 'unknown')


def scanFile(path, lang, skip_comments=True):
    """Return a list of Finding for one file."""
    findings = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as handle:
            lines = handle.readlines()
    except (IOError, OSError):
        return findings

    for index, line in enumerate(lines, 1):
        if len(line) > 1000:
            continue
        if skip_comments and COMMENT_RE.match(line):
            continue
        for rule, pattern in COMPILED:
            if ANY not in rule['langs'] and lang not in rule['langs']:
                continue
            if pattern.search(line):
                findings.append(Finding(rule, path, index, line))
    return findings


def scanDirectory(root, include_unknown=False, skip_comments=True, progress=None,
                  extra_ignore=None):
    """Scan every source file under root. Returns (findings, files_scanned)."""
    findings = []
    scanned = 0
    ignore = loadIgnorePatterns(root) + list(extra_ignore or [])
    for path, lang in collectFiles(root, include_unknown, ignore):
        findings.extend(scanFile(path, lang, skip_comments))
        scanned += 1
        if progress and scanned % 50 == 0:
            progress(scanned, len(findings))
    return findings, scanned
