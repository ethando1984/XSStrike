"""Regression tests for the static-scanner LLM prompt-injection rules
(core/staticScanner.py: llm-prompt-untrusted, llm-call-untrusted-input).

Self-contained: writes small fixture files to a temp dir, runs the static
scanner directly (no network, no extra deps) and asserts that vulnerable
prompt-building / LLM-call code is flagged as CWE-1427 while safe code that
keeps untrusted input out of the instruction context is not.

Run directly:   python tests/test_static_prompt_injection.py
Or via pytest:  pytest tests/test_static_prompt_injection.py
"""
import os
import sys
import shutil
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.staticScanner import scanDirectory

VULN_PY = (
    'import openai\n'
    'from flask import request\n'
    'def handle():\n'
    '    user = request.args.get("q")\n'
    '    prompt = "You are a helpful bot. Answer: " + user\n'
    '    system_prompt = f"Rules: {rules()} User said: {user}"\n'
    '    return openai.ChatCompletion.create(model="gpt-4", '
    'messages=[{"role":"user","content": request.args.get("m")}])\n'
)

VULN_JS = (
    'const answer = await openai.chat.completions.create({ model: "gpt-4", '
    'messages: [{ role: "user", content: req.body.message }] });\n'
)

SAFE_PY = (
    'import openai\n'
    'SYSTEM_PROMPT = "You are a helpful assistant."\n'
    'def handle(user_message):\n'
    '    return openai.ChatCompletion.create(\n'
    '        model="gpt-4",\n'
    '        messages=[\n'
    '            {"role": "system", "content": SYSTEM_PROMPT},\n'
    '            {"role": "user", "content": user_message},\n'
    '        ],\n'
    '    )\n'
)


def _scan(files):
    tmp = tempfile.mkdtemp(prefix='xsstrike_pi_static_')
    try:
        for name, content in files.items():
            with open(os.path.join(tmp, name), 'w') as handle:
                handle.write(content)
        findings, _ = scanDirectory(tmp)
        return findings
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_vulnerable_prompt_building_is_flagged():
    findings = _scan({'vuln.py': VULN_PY})
    ids = [f.rule_id for f in findings]
    assert ids.count('llm-prompt-untrusted') >= 2, \
        'Expected the concatenated and f-string prompts to be flagged, got: %s' % ids
    assert all(f.cwe == 'CWE-1427' for f in findings if f.rule_id.startswith('llm-')), \
        'LLM findings must be tagged CWE-1427'


def test_untrusted_llm_call_is_flagged_single_line():
    findings = _scan({'app.js': VULN_JS})
    ids = [f.rule_id for f in findings]
    assert 'llm-call-untrusted-input' in ids, \
        'Expected a single-line untrusted LLM call to be flagged, got: %s' % ids


def test_safe_llm_usage_is_not_flagged():
    findings = _scan({'safe.py': SAFE_PY})
    llm_ids = [f.rule_id for f in findings if f.rule_id.startswith('llm-')]
    assert not llm_ids, \
        'Safe LLM usage produced false positives: %s' % llm_ids


if __name__ == '__main__':
    test_vulnerable_prompt_building_is_flagged()
    print('[+] test_vulnerable_prompt_building_is_flagged passed')
    test_untrusted_llm_call_is_flagged_single_line()
    print('[+] test_untrusted_llm_call_is_flagged_single_line passed')
    test_safe_llm_usage_is_not_flagged()
    print('[+] test_safe_llm_usage_is_not_flagged passed')
    print('All static prompt-injection rule tests passed.')
