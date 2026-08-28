#!/usr/bin/env python
"""Run a STIG audit against text captured from a device instead of connecting
to it.

Every check in l2_stig_audit.py is a pure function of command output, so the
only part of an audit that needs a live session is collecting that output.
This module supplies a stand-in for a Netmiko connection that serves output
from a capture file, which lets the audit run where the device isn't reachable
- or where nothing may be pointed at the network but an already-approved
terminal emulator. Collect the file by logging a SecureCRT session and running
the commands in AUDIT_COMMANDS_L2S; both the delimited form this project's own
capture tooling writes and a plain session log are accepted.

A capture is a verbatim copy of a device's configuration. On a production
network that means real addressing, hostnames and password hashes, so captures
belong in the gitignored captures/ directory and nowhere near a commit.
"""

import os
import re

import netauto

CAPTURE_DIR = os.path.join(netauto.PROJECT_ROOT, 'captures')

# The complete set of commands an L2S audit reads. Four rules need live state
# that never appears in running-config: user VLANs for V-220633/635, the STP
# root port for V-220629 (Root Guard must never be pushed there), the VTP
# password for V-220624 and the SNMPv3 users for V-220604/605 - IOS classic
# never writes `snmp-server user` to running-config at all. Anything added to
# a discovery step in l2_stig_audit.py has to be added here too, or a capture
# that looks complete will be missing it.
AUDIT_COMMANDS_L2S = (
    'show running-config',
    'show vlan brief',
    'show spanning-tree',
    'show vtp password',
    'show snmp user',
)

# Written before each command's output by the capture tooling. The leading '!'
# makes the whole line an IOS comment, so a capture pasted into a terminal by
# mistake is inert rather than interpreted.
DELIMITER_PREFIX = '!===== netauto-capture: '
DELIMITER_SUFFIX = ' ====='

# A prompt line: hostname, then '#' or '>'. Used only to recognise the command
# echo in a plain session log, and to drop the trailing prompt from a section.
PROMPT = r'^\S*[#>]\s*'


class CaptureError(Exception):
    """A capture file is missing, malformed, or doesn't cover a command the
    audit asked for. Always raised rather than degrading to empty output: a
    check handed '' returns a verdict with the same confidence as one handed
    real config, and a false PASS on a rule nobody re-reads is worse than a
    crash."""


def format_delimiter(command):
    """The delimiter line introducing `command`'s output in a capture file."""
    return f'{DELIMITER_PREFIX}{command}{DELIMITER_SUFFIX}'


def render(outputs):
    """Render {command: output} into capture-file text.

    The counterpart to parse(), and the reason an offline run can be checked
    against a live one: audit a switch with --capture-to, re-run the same audit
    with --from-capture against the file it wrote, and any difference in the
    two reports is a defect in this module rather than a difference between
    the switches."""
    blocks = []
    for command, output in outputs.items():
        blocks.append(format_delimiter(command))
        blocks.append(str(output).rstrip('\n'))
        blocks.append('')
    return '\n'.join(blocks)


def write(path, outputs):
    """Write a capture file, creating its parent directory if needed."""
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as capture_file:
        capture_file.write(render(outputs))
    return path


def _normalise(command):
    """Collapse whitespace so 'show  vlan brief' and 'show vlan brief' match."""
    return ' '.join(command.split())


def _trim_blank_edges(text):
    """Drop leading and trailing blank lines without touching indentation -
    running-config leans on leading spaces to delimit interface blocks, so a
    plain .strip() would corrupt the first line of a section."""
    lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return '\n'.join(lines)


def _drop_trailing_prompt(text):
    """Remove a trailing bare prompt line ('S1#'). Netmiko strips the prompt
    from send_command()'s return value, so a capture has to as well or checks
    anchored to end-of-output behave differently offline than they did live."""
    lines = text.split('\n')
    while lines and re.match(PROMPT + r'$', lines[-1]):
        lines.pop()
    return '\n'.join(lines)


def _reject_paginated(text, source):
    """Refuse a capture taken without 'terminal length 0'. A --More-- prompt
    truncates output mid-config and leaves the pager's backspace padding
    behind; the audit would read a partial running-config as the whole thing
    and fail every rule whose evidence sat past the first screen."""
    if re.search(r'--\s*[Mm]ore\s*--', text):
        raise CaptureError(
            f'{source} contains a --More-- pager prompt, so its output is truncated.\n'
            "Run 'terminal length 0' before the show commands and capture again."
        )


def _split_on_delimiters(text):
    """Parse the delimited form. Returns None if the file carries no delimiters
    at all, so the caller can fall back to reading it as a session log."""
    pattern = re.compile(
        '^' + re.escape(DELIMITER_PREFIX) + r'(.+?)' + re.escape(DELIMITER_SUFFIX) + r'\s*$',
        re.M,
    )
    matches = list(pattern.finditer(text))
    if not matches:
        return None
    sections = {}
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        sections[_normalise(match.group(1))] = text[match.end():end]
    return sections


def _split_on_prompt_echo(text, known_commands):
    """Parse a plain SecureCRT session log, splitting on the echoed command.

    Only the commands actually being looked for are treated as separators. A
    generic 'prompt followed by anything' pattern would split inside
    running-config output, which is full of lines that read like commands -
    and each bogus split would silently shorten the section before it."""
    alternation = '|'.join(
        re.escape(command) for command in sorted(known_commands, key=len, reverse=True)
    )
    pattern = re.compile(PROMPT + f'({alternation})' + r'\s*$', re.M)
    matches = list(pattern.finditer(text))
    if not matches:
        return {}
    sections = {}
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        sections[_normalise(match.group(1))] = text[match.end():end]
    return sections


def parse(text, known_commands=AUDIT_COMMANDS_L2S, source='capture'):
    """Parse capture text into {command: output}, trying the delimited form
    first and falling back to a plain session log."""
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    _reject_paginated(text, source)
    sections = _split_on_delimiters(text)
    if sections is None:
        sections = _split_on_prompt_echo(text, known_commands)
    return {
        command: _trim_blank_edges(_drop_trailing_prompt(_trim_blank_edges(output)))
        for command, output in sections.items()
    }


class CaptureSession:
    """Stands in for a Netmiko connection, serving output from a capture.

    Only send_command() and disconnect() are implemented, which is all the
    audit path uses - stig_common.run_stig_audit, discover_user_vlans and
    discover_root_port_interfaces all reach a device solely through those two.
    That is what lets those functions run offline unmodified."""

    def __init__(self, sections, source):
        self._sections = {_normalise(k): v for k, v in sections.items()}
        self.source = source

    def send_command(self, command, *_args, **_kwargs):
        key = _normalise(command)
        if key not in self._sections:
            available = ', '.join(sorted(self._sections)) or '(none)'
            raise CaptureError(
                f"{self.source} has no output for '{command}'.\n"
                f'It covers: {available}\n'
                'Capture that command and try again - the audit will not guess at '
                'output it was not given.'
            )
        return self._sections[key]

    def disconnect(self):
        """No-op. Present so the audit's connect/read/disconnect flow runs
        unchanged offline rather than needing a branch at every call site."""


def load(path, required_commands=AUDIT_COMMANDS_L2S):
    """Read a capture file and return a CaptureSession.

    Every command in required_commands must be present. Validating up front
    means a capture missing 'show snmp user' is rejected before the audit
    prints its first verdict, rather than 50 rules in."""
    if not os.path.exists(path):
        raise CaptureError(f'No such capture file: {path}')
    with open(path, encoding='utf-8', errors='replace') as capture_file:
        text = capture_file.read()

    source = os.path.basename(path)
    sections = parse(text, required_commands, source=source)
    if not sections:
        raise CaptureError(
            f'{source} has no recognisable command output.\n'
            'Expected either delimiter lines written by the capture tooling '
            f'("{format_delimiter("show running-config")}"), or a session log '
            'showing each command echoed after the device prompt.'
        )

    missing = [
        command for command in required_commands
        if _normalise(command) not in {_normalise(k) for k in sections}
    ]
    if missing:
        raise CaptureError(
            f'{source} is missing output for: {", ".join(missing)}\n'
            f'It covers: {", ".join(sorted(sections))}\n'
            'An audit run against a partial capture would report those rules '
            'against empty output, so it is refused rather than reported.'
        )

    empty = [command for command in required_commands if not sections[_normalise(command)].strip()]
    if empty:
        raise CaptureError(
            f'{source} has empty output for: {", ".join(empty)}\n'
            'A command that returned nothing is indistinguishable from a feature '
            'that is switched off, so this is refused rather than audited.'
        )
    return CaptureSession(sections, source)
