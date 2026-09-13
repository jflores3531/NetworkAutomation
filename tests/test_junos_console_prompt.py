"""Tests for the Junos console prompt pattern in lab/rebuild_lab.py.

The console text below is real, trimmed from the capture of the JSW1 bootstrap
that died on 2026-09-13 with "no prompt back after 'set system domain-name
lab.local' within 60s". The prompt was there. Junos had redrawn the line for
its ZTP chatter and ended it with three carriage returns, and a pattern that
allowed only one never saw it.

Needs pyyaml, because rebuild_lab imports it. Run directly:
    python tests/test_junos_console_prompt.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lab'))
from rebuild_lab import JUNOS_CLI_PROMPT  # noqa: E402

FLAGS = re.I | re.M
PAD = ' ' * 80

# What followed the echo of `set system domain-name lab.local`: the [edit]
# banner, the prompt redrawn with padding and \r\r\r\n, then chatter.
REDRAWN_PROMPT = (
    ' \r\n[edit]\r\nroot# ' + PAD + '\r\r\r\n'
    'Auto Image Upgrade: DHCP INET6 Client State Reset : fxp0.0' + PAD + '\r\r\r\n'
)

# Chatter with no prompt in it at all - must never be taken for one.
CHATTER_ONLY = (
    '\r\n' + ' ' * 79 + '\r\r\r\n'
    'Auto Image Upgrade: No DHCP Client in bound state, reset all DHCP clients' + PAD + '\r\r\r\n'
    + ' ' * 79 + '\r\r\r\n'
    'Auto Image Upgrade: DHCP INET6 Client State Reset : fxp0.0' + PAD + '\r\r\r\n'
    '"delete chassis auto-image-upgrade"  and commit' + ' ' * 73 + '\r\r\r\n'
)

failures = []


def check(label, condition):
    print(f'  {"ok  " if condition else "FAIL"} {label}')
    if not condition:
        failures.append(label)


print('the prompt Junos redraws while ZTP chatter runs')
check('a prompt ending in three carriage returns is recognised',
      re.search(JUNOS_CLI_PROMPT, REDRAWN_PROMPT, FLAGS) is not None)
check('and the pattern that allowed one carriage return did miss it',
      re.search(r'[\r\n][\w.-]*@?[\w.-]*[>#][ \t]*(\r?\n|$)', REDRAWN_PROMPT, FLAGS) is None)

print('the prompts that already worked')
check('a plain prompt as the last thing received',
      re.search(JUNOS_CLI_PROMPT, '\r\n[edit]\r\nroot# ', FLAGS) is not None)
check('an operational prompt followed by one CRLF',
      re.search(JUNOS_CLI_PROMPT, 'set cli screen-length 0\r\nScreen length set to 0\r\nroot> \r\n', FLAGS) is not None)
check('a named user and host',
      re.search(JUNOS_CLI_PROMPT, '\r\nadmin@JSW1> ', FLAGS) is not None)

print('things that are not a prompt')
check('ZTP chatter alone',
      re.search(JUNOS_CLI_PROMPT, CHATTER_ONLY, FLAGS) is None)

print(f'\n{len(failures)} FAILED: {", ".join(failures)}' if failures else '\nall checks passed')
sys.exit(1 if failures else 0)
