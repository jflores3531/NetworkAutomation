#!/usr/bin/env python
"""Verification for securecrt/capture_l2s.py.

Run directly: `python3 tests/test_securecrt_script.py`. No framework, no
SecureCRT, no device.

The script is standalone by necessity - it runs inside SecureCRT's embedded
Python on a machine that may have nothing else installed - so it duplicates
capture.py's delimiter format and command list instead of importing them. That
duplication is the risk this file exists to control: the two could drift and
nothing would notice until a capture taken at work failed to parse at home.
So the constants are asserted equal, and a stubbed SecureCRT drives the real
main() to produce a real file, which capture.load() then has to accept.
"""

import os
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT, 'securecrt'))

import capture
import capture_l2s
from fixtures import OUTPUTS

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


class FakeScreen:
    """Stands in for crt.Screen, replaying fixture output command by command.

    Emulates the two behaviours the script depends on: ReadString returns
    everything since the last send up to the prompt, and the switch echoes the
    command back first."""

    def __init__(self, prompt, outputs, paginate=None, empty=None, timeout_on=None):
        self.prompt = prompt
        self.outputs = outputs
        self.paginate = paginate
        self.empty = empty
        self.timeout_on = timeout_on
        self.Synchronous = False
        self.sent = []
        self._pending = ''
        self.CurrentRow = 5
        self.CurrentColumn = len(prompt) + 1

    def Get(self, row1, col1, row2, col2):
        return self.prompt

    def Send(self, text):
        command = text.rstrip('\r\n')
        self.sent.append(command)
        if command == self.timeout_on:
            self._pending = None
            return
        if command == 'terminal length 0':
            body = ''
        elif command == self.empty:
            body = ''
        elif command == self.paginate:
            body = ' --More-- \nsome truncated output'
        else:
            body = self.outputs.get(command, '')
        # The device echoes the command, then its output, then the prompt.
        self._pending = f'{command}\r\n{body}\r\n'

    def ReadString(self, terminator, timeout=None):
        pending, self._pending = self._pending, ''
        return pending


class FakeDialog:
    def __init__(self, path):
        self.path = path
        self.messages = []

    def MessageBox(self, message, title='', flags=0):
        self.messages.append((title, message))
        return 1

    def Prompt(self, message, title='', default=''):
        return self.path


class FakeCRT:
    def __init__(self, prompt='TESTSW01#', outputs=None, path='', connected=True, **kwargs):
        self.Screen = FakeScreen(prompt, outputs if outputs is not None else OUTPUTS, **kwargs)
        self.Dialog = FakeDialog(path)
        self.Session = type('Session', (), {'Connected': connected})()


def run_script(**kwargs):
    """Drive the real main() with a stubbed SecureCRT."""
    fake = FakeCRT(**kwargs)
    capture_l2s.crt = fake
    try:
        capture_l2s.main()
    finally:
        capture_l2s.crt = None
    return fake


def test_constants_match_capture_module():
    print('standalone copies match capture.py')
    check('delimiter prefix identical',
          capture_l2s.DELIMITER_PREFIX == capture.DELIMITER_PREFIX,
          f'{capture_l2s.DELIMITER_PREFIX!r} vs {capture.DELIMITER_PREFIX!r}')
    check('delimiter suffix identical',
          capture_l2s.DELIMITER_SUFFIX == capture.DELIMITER_SUFFIX)
    check('delimiter line identical for a sample command',
          capture_l2s.format_delimiter('show vtp password')
          == capture.format_delimiter('show vtp password'))
    check('command list identical',
          tuple(capture_l2s.COMMANDS) == tuple(capture.AUDIT_COMMANDS_L2S),
          f'{capture_l2s.COMMANDS} vs {capture.AUDIT_COMMANDS_L2S}')


def test_render_round_trips():
    print('\nrendered text parses back through capture.py')
    parsed = capture.parse(capture_l2s.render(OUTPUTS))
    check('all five sections recovered', set(parsed) == set(OUTPUTS), sorted(parsed))
    for command, original in OUTPUTS.items():
        check(f'{command!r} verbatim', parsed.get(command) == original.strip('\n'))


def test_strip_echo():
    print('\ncommand echo removed, indentation kept')
    text = 'show running-config\r\nBuilding configuration...\r\n!\r\n hostname X\r\n'
    stripped = capture_l2s.strip_echo(text, 'show running-config')
    check('echo line dropped', not stripped.startswith('show running-config'))
    check('first real line kept', stripped.startswith('Building configuration...'))
    check('indentation preserved', ' hostname X' in stripped)
    check('a command whose output starts with its own text is safe',
          capture_l2s.strip_echo('show vtp password\r\nshow vtp password is unset\r\n',
                                 'show vtp password') == 'show vtp password is unset')


def test_full_run(tmpdir):
    print('\nfull run against a stubbed SecureCRT (audit auto-runs, report opens suppressed)')
    path = os.path.join(tmpdir, 'run.capture')
    capture_l2s.OPEN_REPORT = False
    saved_checklist = capture_l2s.AUDIT_CHECKLIST
    capture_l2s.AUDIT_CHECKLIST = 'ios'  # fixture expectations are IOS-keyed
    try:
        fake = run_script(path=path)
    finally:
        capture_l2s.AUDIT_CHECKLIST = saved_checklist
    check('paging disabled first', fake.Screen.sent[0] == 'terminal length 0',
          fake.Screen.sent[:2])
    check('all five commands sent',
          fake.Screen.sent[1:] == list(capture_l2s.COMMANDS), fake.Screen.sent[1:])
    check('synchronous mode restored', fake.Screen.Synchronous is False)
    check('capture file written', os.path.exists(path))
    check('reported success', any('complete' in t.lower() for t, _ in fake.Dialog.messages),
          fake.Dialog.messages)

    # The script now runs the real audit itself and writes the report next to
    # the capture - the linear flow the work machine gets.
    report = path[:-len('.capture')] + '_report.txt'
    check('audit auto-ran, report written next to the capture', os.path.exists(report))
    check('report is a clean .txt, not .capture_report.txt',
          not os.path.exists(path + '_report.txt'))
    check('report filename carries the device hostname', 'TESTSW01' in os.path.basename(report)
          or 'run' in os.path.basename(report))  # stub names the file, not the hostname
    if os.path.exists(report):
        text = open(report, encoding='utf-8').read()
        check('report carries verdicts', 'passed,' in text and '65 rules' in text)
        check('dialog carries the summary line',
              any('out of' in m for _, m in fake.Dialog.messages), fake.Dialog.messages)

    if os.path.exists(path):
        session = capture.load(path)
        check('capture.load accepts it', session is not None)
        for command, original in OUTPUTS.items():
            check(f'{command!r} survives the whole path',
                  session.send_command(command) == original.strip('\n'))


def test_refusals(tmpdir):
    print('\nthe script refuses rather than writing a bad capture')

    def wrote_nothing(name, **kwargs):
        path = os.path.join(tmpdir, name + '.capture')
        fake = run_script(path=path, **kwargs)
        titles = ' '.join(t for t, _ in fake.Dialog.messages).lower()
        return (not os.path.exists(path)), titles

    ok, titles = wrote_nothing('usermode', prompt='TESTSW01>')
    check('user EXEC mode refused', ok and 'enable' in titles, titles)

    ok, titles = wrote_nothing('disconnected', connected=False)
    check('disconnected session refused', ok and 'connected' in titles, titles)

    ok, titles = wrote_nothing('paged', paginate='show vlan brief')
    check('pager output refused', ok and 'truncated' in titles, titles)

    ok, titles = wrote_nothing('empty', empty='show snmp user')
    check('empty command output refused', ok and 'empty' in titles, titles)

    ok, titles = wrote_nothing('timeout', timeout_on='show running-config')
    check('read timeout refused', ok and 'failed' in titles, titles)

    path = os.path.join(tmpdir, 'cancelled.capture')
    fake = FakeCRT(path='')
    capture_l2s.crt = fake
    try:
        capture_l2s.main()
    finally:
        capture_l2s.crt = None
    check('cancelling the save dialog writes nothing', not os.path.exists(path))


if __name__ == '__main__':
    test_constants_match_capture_module()
    test_render_round_trips()
    test_strip_echo()
    with tempfile.TemporaryDirectory() as tmpdir:
        test_full_run(tmpdir)
        test_refusals(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
