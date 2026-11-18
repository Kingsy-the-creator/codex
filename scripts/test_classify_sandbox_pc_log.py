"""Adversarial log examples, not Windows executions or feature tests."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('classifier', Path(__file__).with_name('classify-sandbox-pc-log.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def output(kind='capture'):
    return (f'running 1 test\ntest {module.TESTS[kind]} ... '
            'capture pwsh codex_home=C:\\fixture\n'
            'capture pwsh exit_code=0\ncapture pwsh timed_out=false\nok\n'
            'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 279 filtered out; finished in 0.50s\n')


class EvidenceClassificationTests(unittest.TestCase):
    def test_cases(self):
        good = output()
        cases = [
            ('complete capture', good, 'capture', 0, False, 'REPORTED_PASS'),
            ('tty qualified', output('tty'), 'tty', 0, False, 'REPORTED_PASS'),
            ('nonzero exit', good, 'capture', 101, False, 'FAILED'),
            ('lost exit', good, 'capture', None, False, 'INCOMPLETE'),
            ('timeout', good, 'capture', 0, True, 'TIMEOUT'),
            ('zero tests', good.replace('1 passed', '0 passed'), 'capture', 0, False, 'INVALID_SCOPE'),
            ('ignored', good.replace('0 ignored', '1 ignored'), 'capture', 0, False, 'INVALID_SCOPE'),
            ('multiple', good.replace('1 passed', '2 passed'), 'capture', 0, False, 'INVALID_SCOPE'),
            ('failed summary', good.replace('ok. 1 passed; 0 failed', 'FAILED. 0 passed; 1 failed'), 'capture', 0, False, 'FAILED'),
            ('skip', good + 'skipping PowerShell 7 is not installed\n', 'capture', 0, False, 'PREREQUISITE_OR_SKIP'),
            ('missing body', good.replace('capture pwsh timed_out=false', ''), 'capture', 0, False, 'BODY_UNCONFIRMED'),
            ('wrong test', good.replace(module.TESTS['capture'], module.TESTS['tty']), 'capture', 0, False, 'INVALID_SCOPE'),
            ('truncated', good.split('test result:')[0], 'capture', 0, False, 'INCOMPLETE'),
            ('missing run header', good.replace('running 1 test\n', ''), 'capture', 0, False, 'INVALID_SCOPE'),
            ('wrong run count', good.replace('running 1 test', 'running 0 tests'), 'capture', 0, False, 'INVALID_SCOPE'),
            ('two invocations', good + good, 'capture', 0, False, 'INVALID_SCOPE'),
            ('nested result', good + good.splitlines()[-1] + '\n', 'capture', 0, False, 'INVALID_SCOPE'),
            ('quoted success', 'Write-Output "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 279 filtered out;"', 'capture', 0, False, 'INCOMPLETE'),
            ('annotation duplicate', good + '##[notice]' + good.splitlines()[-1] + '\n', 'capture', 0, False, 'REPORTED_PASS'),
            ('colour and timestamp', '\n'.join('2026-11-18T07:00:00.000Z \x1b[32m' + x + '\x1b[0m' for x in good.splitlines()), 'capture', 0, False, 'REPORTED_PASS'),
            ('build failure', 'error: could not compile codex-windows-sandbox\n', 'capture', 101, False, 'INCOMPLETE'),
            # tests.rs: the TTY test's pwsh_path() early return eprintln!s this text, hidden without --nocapture.
            ('tty early return, output captured', output('tty').replace('finished in 0.50s', 'finished in 0.00s'), 'tty', 0, False, 'BODY_UNCONFIRMED'),
            ('tty early return, --nocapture', output('tty').replace('finished in 0.50s', 'finished in 0.00s') + 'skipping sandbox ConPTY lifecycle test: PowerShell 7 is not installed\n', 'tty', 0, False, 'PREREQUISITE_OR_SKIP'),
            ('tty summary without a duration', output('tty').replace(' finished in 0.50s', ''), 'tty', 0, False, 'BODY_UNCONFIRMED'),
        ]
        for label, text, kind, code, timeout, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(module.classify(text, kind, code, timeout)['classification'], expected)

    def test_log_encodings(self):
        """UTF-16 logs from Windows PowerShell 5.1 and damaged bytes are read, not crashed on."""
        with tempfile.TemporaryDirectory() as tmp:
            utf16 = Path(tmp, 'utf16.log')
            utf16.write_text(output(), encoding='utf-16')
            damaged = Path(tmp, 'damaged.log')
            damaged.write_bytes(output().encode('utf-8') + b'\x80\xff\n')
            for log in (utf16, damaged):
                with self.subTest(log=log.name):
                    self.assertEqual(module.classify(module.read_log(log), 'capture', 0)['classification'], 'REPORTED_PASS')


if __name__ == '__main__':
    unittest.main()
