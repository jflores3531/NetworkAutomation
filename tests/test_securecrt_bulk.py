#!/usr/bin/env python
"""Verification for securecrt/capture_l2s_bulk.py - the unattended walker.

Run it directly: `python3 tests/test_securecrt_bulk.py`. No framework, no
SecureCRT, no devices.

What this is guarding. The walker runs for hours with nobody watching, against
production switches, and its output is a compliance result someone signs. The
failure that matters is not a crash - a crash is visible. It is a run that
finishes looking healthy while quietly leaving switches out, or writing captures
that are not what they claim to be. So the checks here are mostly about the
run log being a truthful account of what happened to every session in the list:
offline ones skipped rather than fatal, rejected logins tried twice and no more,
duplicates collapsed on purpose rather than by accident, and a resumed run
picking up exactly what the first one missed.
"""

import io
import os
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)
sys.path.insert(0, os.path.join(PROJECT, 'securecrt'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capture
import capture_l2s
import capture_l2s_bulk as bulk
from fixtures import OUTPUTS

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


class FakeScreen:
    """Replays fixture output command by command, echoing like a real device."""

    def __init__(self, host_outputs):
        self.host_outputs = host_outputs
        self.Synchronous = False
        self.prompt = 'SW#'
        self._pending = ''
        self.CurrentRow = 5
        self.CurrentColumn = len(self.prompt) + 1

    def Get(self, *_args):
        return self.prompt

    def Send(self, text):
        command = text.rstrip('\r\n')
        body = '' if command == 'terminal length 0' else self.host_outputs.get(command, '')
        self._pending = f'{command}\r\n{body}\r\n'

    def ReadString(self, _terminator, timeout=None):
        pending, self._pending = self._pending, ''
        return pending


class FakeSession:
    def __init__(self, crt_stub):
        self.crt = crt_stub
        self.Connected = False

    def Connect(self, connect_string, _suppress=False):
        session = connect_string.split('"')[1]
        self.crt.attempts.append(session)
        outcome = self.crt.behaviour.get(session, 'ok')
        if outcome != 'ok':
            self.crt.last_error = {
                'offline': 'The remote system refused the connection.',
                'rejected': 'Password authentication failed.',
            }[outcome]
            raise Exception(self.crt.last_error)
        self.Connected = True

    def Disconnect(self):
        self.Connected = False

    def SetStatusText(self, _text):
        pass


class FakeDialog:
    def __init__(self, crt_stub):
        self.crt = crt_stub

    def Prompt(self, _message, title='', default='', _password=False):
        if 'scope' in title.lower():
            return self.crt.folder
        return self.crt.output_dir

    def MessageBox(self, message, title='', flags=0):
        self.crt.messages.append((title, message))
        return 6 if flags & 4 else 1  # always answer Yes to the confirm dialog


class FakeCRT:
    def __init__(self, output_dir, behaviour, host_outputs, folder=''):
        self.output_dir = output_dir
        self.behaviour = behaviour
        self.folder = folder
        self.attempts = []
        self.messages = []
        self.last_error = ''
        self.Screen = FakeScreen(host_outputs)
        self.Session = FakeSession(self)
        self.Dialog = FakeDialog(self)

    def GetLastErrorMessage(self):
        return self.last_error


def run_walker(tmpdir, sessions, behaviour, host_outputs=None, folder=''):
    """Drive bulk.main() with a stubbed SecureCRT and a stubbed session list."""
    fake = FakeCRT(tmpdir, behaviour, host_outputs or OUTPUTS, folder)
    bulk.crt = fake
    capture_l2s.crt = fake
    original_find = bulk.find_sessions
    bulk.find_sessions = lambda _filter='': list(sessions)
    try:
        bulk.main()
    finally:
        bulk.find_sessions = original_find
        bulk.crt = None
        capture_l2s.crt = None
    return fake


def log_files(tmpdir):
    """Every run log in the folder, oldest first. One per run."""
    return sorted(os.path.join(tmpdir, name) for name in os.listdir(tmpdir)
                  if name.startswith('run_log_') and name.endswith('.csv'))


def log_rows(tmpdir, which=-1):
    """Rows of one run's log; the newest by default."""
    paths = log_files(tmpdir)
    if not paths:
        return []
    with io.open(paths[which], encoding='utf-8') as handle:
        return [line.strip().split(',') for line in handle.read().splitlines()[1:]]


def outcomes(tmpdir):
    return {row[1].strip('"'): row[3].strip('"') for row in log_rows(tmpdir)}


def test_offline_switches_do_not_stop_the_run(tmpdir):
    """The reason there is no abort. On any given night a good fraction of six
    hundred switches will be unreachable, and a collector that stops at the
    first one never finishes."""
    print('\noffline switches are skipped, not fatal')
    sessions = [('sw-a', '10.0.0.1'), ('sw-b', '10.0.0.2'), ('sw-c', '10.0.0.3')]
    fake = run_walker(tmpdir, sessions, {'sw-b': 'offline'})
    result = outcomes(tmpdir)
    check('the offline switch is logged unreachable',
          result.get('sw-b') == 'unreachable', result)
    check('the run continues past it', result.get('sw-c') == 'captured', result)
    check('reachable switches are captured',
          os.path.exists(os.path.join(tmpdir, '10.0.0.1.capture'))
          and os.path.exists(os.path.join(tmpdir, '10.0.0.3.capture')))
    check('an offline switch leaves no capture behind',
          not os.path.exists(os.path.join(tmpdir, '10.0.0.2.capture')))
    check('offline is not retried', fake.attempts.count('sw-b') == 1, fake.attempts)


def test_rejected_login_is_tried_twice(tmpdir):
    """Two attempts, then move on - deliberately under V-220524's threshold of
    three within 120 seconds, so a wrong credential does not trip the
    15-minute quiet period."""
    print('\na rejected login is retried once, then skipped')
    sessions = [('sw-a', '10.0.1.1'), ('sw-b', '10.0.1.2')]
    fake = run_walker(tmpdir, sessions, {'sw-a': 'rejected'})
    check('exactly two attempts', fake.attempts.count('sw-a') == 2, fake.attempts)
    check('two is below the STIG lockout threshold of three',
          bulk.LOGIN_ATTEMPTS < 3, bulk.LOGIN_ATTEMPTS)
    check('logged as a rejected login',
          outcomes(tmpdir).get('sw-a') == 'login rejected', outcomes(tmpdir))
    check('the run continues', outcomes(tmpdir).get('sw-b') == 'captured')


def test_duplicates_collapsed_and_recorded(tmpdir):
    """Merging a colleague's exported sessions is how the list reaches six
    hundred, so duplicate sessions for one switch are expected. One device
    needs one capture - but the log still has to explain the missing rows."""
    print('\nduplicate sessions for one switch are collapsed, and logged')
    sessions = [('site-a\\sw-1', '10.0.2.1'), ('site-b\\sw-1-copy', '10.0.2.1'),
                ('site-a\\sw-2', '10.0.2.2')]
    fake = run_walker(tmpdir, sessions, {})
    check('the duplicate is never connected to',
          'site-b\\sw-1-copy' not in fake.attempts, fake.attempts)
    check('but it is recorded, not silently dropped',
          outcomes(tmpdir).get('site-b\\sw-1-copy') == 'duplicate', outcomes(tmpdir))
    check('the log accounts for every session in the list',
          len(log_rows(tmpdir)) == len(sessions), log_rows(tmpdir))


def test_not_a_switch_is_refused(tmpdir):
    """A session list will eventually contain a jump host. bash answers every
    command with an error, so nothing is empty and nothing is truncated."""
    print('\na session that is not a Cisco switch writes no capture')
    bash = {command: f'bash: {command.split()[0]}: command not found'
            for command in capture_l2s.COMMANDS}
    run_walker(tmpdir, [('jumphost', '10.0.3.1')], {}, host_outputs=bash)
    check('logged as refused', outcomes(tmpdir).get('jumphost') == 'refused', outcomes(tmpdir))
    check('no capture written', not os.path.exists(os.path.join(tmpdir, '10.0.3.1.capture')))


def test_resume_skips_what_is_done(tmpdir):
    """What makes a five-hour run survivable: a second pass visits only the
    switches that have no capture yet."""
    print('\na re-run picks up only what is missing')
    sessions = [('sw-a', '10.0.4.1'), ('sw-b', '10.0.4.2')]
    run_walker(tmpdir, sessions, {'sw-b': 'offline'})
    check('first pass captured one, missed one',
          os.path.exists(os.path.join(tmpdir, '10.0.4.1.capture'))
          and not os.path.exists(os.path.join(tmpdir, '10.0.4.2.capture')))

    second = run_walker(tmpdir, sessions, {})  # sw-b now reachable
    check('the completed switch is not revisited', 'sw-a' not in second.attempts, second.attempts)
    check('the missed switch is', 'sw-b' in second.attempts, second.attempts)
    check('and is captured on the second pass',
          os.path.exists(os.path.join(tmpdir, '10.0.4.2.capture')))

    # Per-run files, so a log can be counted in a spreadsheet as it stands
    # rather than by picking the newest row per switch out of a history.
    check('each run wrote its own log', len(log_files(tmpdir)) == 2, log_files(tmpdir))
    # ...which only works if a run also accounts for what it skipped. Without
    # those rows the second pass logs one device and loses the other.
    second_run = outcomes(tmpdir)
    check("the second run's log still accounts for both switches",
          len(second_run) == 2, second_run)
    check('the one it skipped is logged as already captured',
          second_run.get('sw-a') == 'already captured', second_run)
    check('the one it collected is logged as captured',
          second_run.get('sw-b') == 'captured', second_run)


def test_capture_is_auditable(tmpdir):
    """The whole point. A file the walker wrote has to load through the same
    path a hand-collected capture does."""
    print('\nwhat the walker writes is what the audit reads')
    run_walker(tmpdir, [('sw-a', '10.0.5.1')], {})
    path = os.path.join(tmpdir, '10.0.5.1.capture')
    try:
        session = capture.load(path)
        ok, detail = True, ''
    except capture.CaptureError as error:
        ok, detail = False, str(error)
    check('capture.load accepts it', ok, detail)
    if ok:
        check('and serves the running-config back',
              session.send_command('show running-config')
              == OUTPUTS['show running-config'].strip('\n'))


def test_stop_file_halts_cleanly(tmpdir):
    print('\nthe STOP file ends a run without killing it mid-command')
    open(os.path.join(tmpdir, bulk.STOP_FILE), 'w').close()
    fake = run_walker(tmpdir, [('sw-a', '10.0.6.1'), ('sw-b', '10.0.6.2')], {})
    check('nothing was connected to', not fake.attempts, fake.attempts)
    check('and the run said so',
          any('stopped early' in message.lower() for _title, message in fake.messages),
          fake.messages)


if __name__ == '__main__':
    for test in (test_offline_switches_do_not_stop_the_run,
                 test_rejected_login_is_tried_twice,
                 test_duplicates_collapsed_and_recorded,
                 test_not_a_switch_is_refused,
                 test_resume_skips_what_is_done,
                 test_capture_is_auditable,
                 test_stop_file_halts_cleanly):
        with tempfile.TemporaryDirectory() as tmpdir:
            test(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
