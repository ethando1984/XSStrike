### Unreleased
- Directory scan (`--scan-dir`) now draws the target as a live directory tree on
  interactive terminals, updating each file's status in place (pending →
  scanning → clean / N findings, coloured by severity) and rolling finding
  totals up onto the parent directories when the scan finishes
  - Falls back to a single live status line when the tree is taller than the
    terminal, and to periodic summaries when output is piped/redirected
- Upgraded the retire.js vulnerable-JS-library database (`db/definitions.json`)
  to the latest upstream (34 → 76 components, current CVEs)
- Hardened the retireJs plugin against the fuller dataset:
  - Skip JS-only regex constructs Python's `re` can't compile instead of
    aborting the scan
  - Report vulnerabilities with a missing `CVE`/`summary` as `N/A` instead
    of crashing
  - Deduplicate findings without the lossy string round-trip that broke on
    quotes/apostrophes in advisory text
  - No longer flag an up-to-date library as "Vulnerable" when only its
    version matched and no known vulnerabilities apply

### 3.2.0
- Added an LLM **prompt injection** scanning mode (`--prompt-injection`)
  with baseline fingerprinting and system-prompt leak heuristics
- Added multi-language **static source code scanning** (`--scan-dir`)
  with `--scan-limit` and `--min-severity` controls
- Added static-scan rules for detecting LLM prompt injection in source
- Added a pre-commit hook that runs `--scan-dir` on staged files
- Improved crawler link discovery with optional headless rendering
- Fixed pip fallback to use `sys.executable` when auto-installing fuzzywuzzy
- Split test dependencies into `requirements-dev.txt`

### 3.1.5
- Fix color bug that resulted in DOM XSS vulnerabilities not
  being reported on certain systems (Windows, macOS, iOS)

### 3.1.4
- Negligible DOM XSS false positives
- x10 Faster crawling by
    - Removing additional request for detecting DOM XSS
    - Skipping testing of a parameter multiple times

### 3.1.3
- Removed browser engine emulation
- Fixed a few bugs
- Added a plugin to scan for outdated JS libraries
- Improved crawling and DOM scanning

### 3.1.2
- Fixed POST data handling
- Support for JSON POST data
- Support for URL rewriting
- Cleaner crawling dashboard
- No more weird characters while scanning DOM
- Better DOM XSS scanning
- Handle unicode while writing to file
- Handle connection reset
- Added ability to add headers from command line
- Fixed issue which caused `foundParams` to not be tested

### 3.1.1
- Fixed a build breaking typo

### 3.1.0
- Various minor enhancements and bug fixes
- Browser engine integration for zero false positives
- Coverage of event handler context

### 3.0.5

- Fixed a bug in HTML Parser
- Ability to add urls from file
- More modular structure
- Show parameter name while bruteforcing
- Fix payload display while using POST method

### 3.0.4

- Fixed a bug in bruteforcer
- Fixed a major bug in HTML Parser
- Added progress bar for bruteforcer
- Code refactor
- Updated signature for Fortiweb WAF

### 3.0.3

- Minor bug fixes
- Proxy Support
- Blind XSS support
- Detection of up to 66 WAFs

### 3.0.2

- Ability to bruteforce payloads from a file
- Verbose output toggle
- Payload encoding: base64
- Handle MemoryError in DOM scanner
- Fixed a bug in bruteforcer

### 3.0.1

- Fixed poc generation
- Better multi js context injection
- Better wrong content type handling
- Handle high variance of context breakers
- Better efficiency check
- Fixed update mechanism
- Added license
- Added --skip switch
- Ignore SSL certificates

### 3.0.0

Production ready stable release with no known bugs

### 3.0-rc-1

- Removed redundant code & imports
- Disable colors in windows and mac
- Fixed user-agent overriding
- Handle wrong content type
- Multi-thread scanning
- Rewritten JavaScript parser to be more accurate
- Handle dynamic number of reflections
- Better regex for locating DOM sources
- Fixed a bug in DOM scanning while crawling
- Flexible crawling with ability to specify threads, depth
- Treat html entity and slash escaping differently
- Other minor bug fixes

### 3.0-beta

Intial beta release for public testing
