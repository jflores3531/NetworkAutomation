#!/usr/bin/env python
"""Verification for capture.py and l2_stig_audit.py's --from-capture path.

Run it directly - `python3 tests/test_capture.py` - from anywhere. No test
framework, matching the rest of this project's dependencies (netmiko, pyyaml,
nothing else), and no device: the whole point of the offline path is that it
needs neither.

What this is guarding. An offline audit is only worth having if it reaches the
same verdicts a live one would, so the central test renders known output into a
capture file, parses it back, and asserts a full audit driven by that file is
byte-identical to one driven by a live-shaped session. Everything else here
guards the ways a capture can be quietly wrong: truncated by a pager, missing a
command, or carrying output for a command the audit never asked for. Those all
have to raise, because a check handed empty text returns a verdict with exactly
the same confidence as one handed real config, and a false PASS nobody re-reads
is worse than a crash.

The fixture below is synthetic and uses RFC 5737 documentation addressing. Real
captures are gitignored and must never be committed - see capture.py.
"""

import contextlib
import io
import os
import subprocess
import sys
import tempfile

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)

import capture
import stig_common

CHECKLIST = os.path.join(PROJECT, 'checklists', 'New Layer 2 switch Checklist.cklb')

RUNNING_CONFIG = """Building configuration...

Current configuration : 4211 bytes
!
version 17.9
service timestamps debug datetime msec localtime show-timezone
service timestamps log datetime msec localtime show-timezone
service password-encryption
!
hostname TESTSW01
!
aaa new-model
aaa authentication login default group radius local
aaa accounting exec default start-stop group radius
!
no ip domain-lookup
ip domain name example.test
!
vtp mode transparent
!
spanning-tree mode rapid-pvst
spanning-tree portfast bpduguard default
!
vlan 10
 name MGMT
!
vlan 20
 name USERS
!
vlan 999
 name NATIVE
!
vlan 1000
 name UNUSED
!
ip dhcp snooping vlan 20
ip dhcp snooping
ip arp inspection vlan 20
!
interface GigabitEthernet1/0/1
 description user port
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast
 spanning-tree bpduguard enable
 ip verify source
!
interface GigabitEthernet1/0/2
 description disabled port
 switchport mode access
 switchport access vlan 1000
 shutdown
!
interface TwentyFiveGigE1/1/1
 description uplink to core
 switchport mode trunk
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20
 ip dhcp snooping trust
 ip arp inspection trust
!
interface Vlan10
 ip address 192.0.2.5 255.255.255.0
!
banner login ^C
You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.
^C
!
line con 0
 exec-timeout 5 0
 logging synchronous
line vty 0 4
 exec-timeout 5 0
 transport input ssh
 session-limit 5
!
logging buffered 64000
logging host 192.0.2.20
logging host 192.0.2.21
logging trap informational
!
ntp authenticate
ntp server 192.0.2.30
ntp server 192.0.2.31
!
snmp-server group STIGGRP v3 priv
!
ip ssh version 2
ip ssh server algorithm mac hmac-sha2-256
ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr
!
end"""

VLAN_BRIEF = """VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active
10   MGMT                             active    Vl10
20   USERS                            active    Gi1/0/1
999  NATIVE                           active
1000 UNUSED                           active    Gi1/0/2
1002 fddi-default                     act/unsup
1003 trcrf-default                    act/unsup
1004 fddinet-default                  act/unsup
1005 trbrf-default                    act/unsup"""

SPANNING_TREE = """VLAN0010
  Spanning tree enabled protocol rstp
  Root ID    Priority    24586
             Address     0011.2233.4455
             Cost        4
             Port        1 (TwentyFiveGigE1/1/1)
             Hello Time  2 sec  Max Age 20 sec  Forward Delay 15 sec

VLAN0020
  Spanning tree enabled protocol rstp
  Root ID    Priority    24596
             Address     0011.2233.4455
             Cost        4
             Port        1 (TwentyFiveGigE1/1/1)
             Hello Time  2 sec  Max Age 20 sec  Forward Delay 15 sec"""

VTP_PASSWORD = 'The VTP password is not configured.'

SNMP_USER = """User name: stigadmin
Engine ID: 800000090300AABBCCDDEEFF
storage-type: nonvolatile        active
Authentication Protocol: SHA
Privacy Protocol: AES128
Group-name: STIGGRP"""

OUTPUTS = {
    'show running-config': RUNNING_CONFIG,
    'show vlan brief': VLAN_BRIEF,
    'show spanning-tree': SPANNING_TREE,
    'show vtp password': VTP_PASSWORD,
    'show snmp user': SNMP_USER,
}

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


def expect_error(name, call, needle):
    """Assert `call` raises CaptureError whose message names the real problem.
    The message matters as much as the raise - these fire on someone else's
    network, where the fix has to be obvious from the text alone."""
    try:
        call()
    except capture.CaptureError as error:
        check(name, needle.lower() in str(error).lower(), f'message was: {error}')
    else:
        check(name, False, 'no CaptureError raised')


class FakeLiveSession:
    """Shaped like the Netmiko connection run_stig_audit would otherwise open."""

    def __init__(self, outputs):
        self.outputs = outputs
        self.disconnected = False

    def send_command(self, command, *_args, **_kwargs):
        return self.outputs[command]

    def disconnect(self):
        self.disconnected = True


def report_from(session, checks):
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        stig_common.run_stig_audit('TESTSW01', None, CHECKLIST, checks, title='STIG audit',
                                   username=None, password=None, session=session)
    return buffer.getvalue()


def test_round_trip():
    print('round-trip: text -> capture file -> parsed text')
    parsed = capture.parse(capture.render(OUTPUTS))
    for command, original in OUTPUTS.items():
        check(f'{command!r} survives verbatim', parsed.get(command) == original.strip('\n'))
    check('no extra sections', set(parsed) == set(OUTPUTS), f'got {sorted(parsed)}')
    # Indentation delimits interface blocks; a plain .strip() would eat it.
    check('interface block indentation preserved',
          ' switchport mode access' in parsed['show running-config'])
    check('CRLF captures normalise',
          capture.parse(capture.render(OUTPUTS).replace('\n', '\r\n'))['show vtp password']
          == VTP_PASSWORD)
    check('whitespace-varied command names still match',
          capture.parse(capture.render({'show  vlan   brief': VLAN_BRIEF}))['show vlan brief']
          == VLAN_BRIEF)


def test_session_log():
    print('\nplain terminal session log, no delimiters')
    log = ''.join(f'TESTSW01#{command}\n{output}\nTESTSW01#\n'
                  for command, output in OUTPUTS.items())
    parsed = capture.parse(log)
    check('all five commands recovered', set(parsed) == set(OUTPUTS), f'got {sorted(parsed)}')
    for command, original in OUTPUTS.items():
        check(f'{command!r} matches the delimited form', parsed.get(command) == original.strip('\n'))
    check('trailing prompt stripped', not parsed['show vtp password'].endswith('#'))
    # running-config is full of lines that read like commands. If any of them
    # were treated as a separator, the section before it would be silently
    # truncated - which is why only the requested commands can split a capture.
    check('running-config not split on its own content',
          parsed['show running-config'].endswith('end')
          and 'hostname TESTSW01' in parsed['show running-config'])


def test_refusals(tmpdir):
    print('\nmalformed captures are refused, not audited')
    paged = capture.render(OUTPUTS).replace('vlan 10\n', 'vlan 10\n --More-- \n', 1)
    expect_error('paginated capture rejected', lambda: capture.parse(paged), 'terminal length 0')

    partial = capture.write(os.path.join(tmpdir, 'partial.capture'),
                            {k: v for k, v in OUTPUTS.items() if k != 'show snmp user'})
    expect_error('missing command rejected', lambda: capture.load(partial), 'show snmp user')

    blank = capture.write(os.path.join(tmpdir, 'blank.capture'),
                          {**OUTPUTS, 'show snmp user': ''})
    expect_error('empty command output rejected', lambda: capture.load(blank), 'empty output')

    expect_error('absent file rejected',
                 lambda: capture.load(os.path.join(tmpdir, 'nope.capture')), 'no such capture')

    good = capture.write(os.path.join(tmpdir, 'good.capture'), OUTPUTS)
    expect_error('unrequested command raises rather than returning empty',
                 lambda: capture.load(good).send_command('show ip interface brief'),
                 'no output for')


def test_equivalence(tmpdir):
    print('\ncapture session vs live-shaped session, same verdicts')
    checks = {
        'V-220596': lambda cfg: ('exec-timeout 5 0' in cfg, 'console exec-timeout'),
        'V-220599': lambda cfg: ('logging buffered 64000' in cfg, 'buffer size'),
        'V-220649': lambda cfg: (None, 'not applicable here'),
        'V-220642': lambda cfg: ('NOT AUTOMATED', 'needs live review'),
    }
    good = capture.write(os.path.join(tmpdir, 'equiv.capture'), OUTPUTS)
    live = FakeLiveSession(OUTPUTS)
    live_report = report_from(live, checks)
    check('reports byte-identical', live_report == report_from(capture.load(good), checks))
    check('live session was disconnected', live.disconnected)
    check('report is non-trivial', live_report.count('\n') > 100 and 'passed' in live_report)


def test_end_to_end(tmpdir):
    print('\nend-to-end: l2_stig_audit.py --from-capture, every rule in the checklist')
    good = capture.write(os.path.join(tmpdir, 'e2e.capture'), OUTPUTS)
    result = subprocess.run(
        [sys.executable, os.path.join(PROJECT, 'l2_stig_audit.py'), 'TESTSW01',
         '--from-capture', good, '--non-user-vlans', '1,10,999,1000'],
        capture_output=True, text=True, cwd=PROJECT, timeout=120)
    check('script exits cleanly', result.returncode == 0, result.stderr[-1500:])
    check('no connection attempted', 'Connecting to device' not in result.stdout)
    check('capture source named in output', 'e2e.capture' in result.stdout)
    summary = [line for line in result.stdout.splitlines() if 'out of' in line]
    check('summary line present', bool(summary), result.stdout[:400])
    if summary:
        print(f'       {summary[0].strip()}')
    check('every checklist rule reported', '65 rules' in result.stdout)

    print('\nmutually exclusive flags')
    clash = subprocess.run(
        [sys.executable, os.path.join(PROJECT, 'l2_stig_audit.py'), 'S1',
         '--from-capture', good, '--capture-to', os.path.join(tmpdir, 'x.capture')],
        capture_output=True, text=True, cwd=PROJECT, timeout=60)
    check('--from-capture with --capture-to is refused', clash.returncode == 2, clash.stdout)


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as tmpdir:
        test_round_trip()
        test_session_log()
        test_refusals(tmpdir)
        test_equivalence(tmpdir)
        test_end_to_end(tmpdir)
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
