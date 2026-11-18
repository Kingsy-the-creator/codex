#!/usr/bin/env python3
"""Classify one exact legacy test log; never certify a PC or a security fix.

Input is a single invocation's complete output plus its captured exit code.
No third-party packages. This is deliberately conservative about no-op passes.
"""
import argparse
import json
import re
from pathlib import Path

TESTS = {
    'capture': 'unified_exec::tests::legacy_capture_emits_output_and_preserves_descendant_after_normal_exit',
    'tty': 'unified_exec::tests::legacy_tty_job_terminates_and_preserves_descendants',
}
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
STAMP = re.compile(r'^\d{4}-\d\d-\d\dT\S+Z ')
SUMMARY = re.compile(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;(?: finished in (\d+(?:\.\d+)?)s)?')
# The TTY test's only early return (pwsh_path() is None) passes almost instantly, and libtest
# hides its skip text unless --nocapture is used. Its real body starts several sandboxed
# PowerShell processes, so a pass faster than this floor cannot have exercised it.
TTY_MIN_SECONDS = 0.25


def read_log(path):
    """Return a captured log as text without crashing triage on its encoding.

    Windows PowerShell 5.1 redirection writes UTF-16 with a byte-order mark; PowerShell 7
    writes UTF-8. Undecodable bytes become U+FFFD so a damaged log is still classified.
    """
    data = Path(path).read_bytes()
    if data.startswith((b'\xff\xfe', b'\xfe\xff')):
        return data.decode('utf-16', errors='replace')
    return data.decode('utf-8-sig', errors='replace')


def classify(text, kind, exit_code, timed_out=False):
    lines = [STAMP.sub('', ANSI.sub('', x)).strip('\ufeff\r') for x in text.splitlines()]
    # Keep annotations and echoed commands unrecognised: they duplicate or quote results.
    summaries = [m.groups() for line in lines if (m := SUMMARY.match(line))]
    name = TESTS[kind]
    starts = [line for line in lines if line.startswith('test ' + name + ' ...')]
    invocations = [line for line in lines if re.fullmatch(r'running \d+ tests?', line)]
    result = {'test': name, 'exit_code': exit_code, 'timed_out': timed_out,
              'classification': 'INCOMPLETE', 'reasons': [],
              'limit': 'Log classification only. Revision, environment, body execution and isolation still require review.'}
    if timed_out:
        result.update(classification='TIMEOUT', reasons=['No pass can be accepted after a timeout.'])
    elif not summaries:
        result['reasons'] = ['No completed Rust test summary; inspect build, startup or truncated output.']
    elif len(summaries) != 1 or len(starts) != 1 or invocations != ['running 1 test']:
        result.update(classification='INVALID_SCOPE', reasons=['Need one exact named test and one final summary from one invocation.'])
    else:
        status, passed, failed, ignored, measured, _, seconds = summaries[0]
        counts = tuple(map(int, (passed, failed, ignored, measured)))
        if exit_code is None:
            result['reasons'] = ['The native exit code was not captured.']
        elif exit_code != 0 or status == 'FAILED' or int(failed):
            result.update(classification='FAILED', reasons=['Native exit code or test summary records failure.'])
        elif counts != (1, 0, 0, 0):
            result.update(classification='INVALID_SCOPE', reasons=['Expected 1 passed, 0 failed, 0 ignored and 0 measured.'])
        elif any(re.search(r'\bskipp(?:ing|ed)\b|PowerShell 7 is not installed', line, re.I) for line in lines):
            result.update(classification='PREREQUISITE_OR_SKIP', reasons=['Output mentions a skip; do not count it as exercised coverage.'])
        elif kind == 'capture' and not all(any(marker in line for line in lines) for marker in ('capture pwsh codex_home=', 'capture pwsh exit_code=0', 'capture pwsh timed_out=false')):
            result.update(classification='BODY_UNCONFIRMED', reasons=['Capture-body evidence is missing even though the harness reports a pass.'])
        elif kind == 'tty' and (seconds is None or float(seconds) < TTY_MIN_SECONDS):
            result.update(classification='BODY_UNCONFIRMED', reasons=[f'The TTY pass has no duration or finished in under {TTY_MIN_SECONDS}s, which fits the missing-PowerShell early return (its skip text is hidden unless --nocapture is used), not the lifecycle body.'])
        else:
            result.update(classification='REPORTED_PASS', reasons=['One exact harness test reports success.'])
            if kind == 'tty':
                result['reasons'].append('This test has no success-body marker; verify pinned source and the exact PowerShell path before and after the run. Both lifecycle assertions must have executed.')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--test', choices=TESTS, required=True)
    parser.add_argument('--exit-code', type=int)
    parser.add_argument('--timed-out', action='store_true')
    args = parser.parse_args()
    result = classify(read_log(args.log), args.test, args.exit_code, args.timed_out)
    print(json.dumps(result, indent=2))
    return 0 if result['classification'] == 'REPORTED_PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
