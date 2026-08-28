# $language = "Python3"
# $interface = "1.0"

"""Collect an L2 switch STIG capture from inside SecureCRT.

Run this from an already-connected, already-authenticated SecureCRT session
(Script > Run...). It types five read-only show commands into that session and
writes their output to a capture file, which l2_stig_audit.py then audits
offline:

    python3 l2_stig_audit.py SW01 --from-capture <file>

Nothing is configured and nothing is saved. The only command sent that is not a
show is `terminal length 0`, which disables paging for this session only - it is
session-scoped, so it neither persists nor affects anyone else logged in.

This file is deliberately standalone. It imports nothing from the rest of the
project, because it runs inside SecureCRT's own embedded Python on a machine
that may have nothing else installed - no netmiko, no repository, no venv.
Netmiko in particular is neither needed nor wanted here: it would open its own
SSH connection, which is the thing SecureCRT is being used to avoid. The
capture file is the only interface between this script and the audit.

Because it is standalone, the delimiter format below is duplicated from
capture.py rather than imported. tests/test_securecrt_script.py asserts the two
stay identical, so the duplication cannot drift silently.
"""

# The five commands an L2S audit reads. Four of these exist because the state
# is not in running-config: user VLANs, the STP root port, the VTP password,
# and the SNMPv3 users. Keep in step with capture.AUDIT_COMMANDS_L2S.
COMMANDS = (
    'show running-config',
    'show vlan brief',
    'show spanning-tree',
    'show vtp password',
    'show snmp user',
)

# Must match capture.py's DELIMITER_PREFIX / DELIMITER_SUFFIX exactly. The
# leading '!' makes each line an IOS comment, so a capture pasted into a
# terminal by accident is inert rather than interpreted.
DELIMITER_PREFIX = '!===== netauto-capture: '
DELIMITER_SUFFIX = ' ====='

# `show running-config` on a large switch is the slow one. Generous, because
# the cost of a short timeout is a truncated capture that still looks valid.
READ_TIMEOUT_SECONDS = 180


def format_delimiter(command):
    """The delimiter line introducing a command's output."""
    return DELIMITER_PREFIX + command + DELIMITER_SUFFIX


def normalise(text):
    """CRLF to LF. SecureCRT hands back the terminal's line endings; the audit
    normalises anyway, but writing LF keeps the file diffable."""
    return text.replace('\r\n', '\n').replace('\r', '\n')


def strip_echo(text, command):
    """Drop the echoed command from the front of a command's output.

    ReadString returns everything typed and received since the send, which
    starts with the switch echoing the command back. Netmiko strips this and so
    must a capture, or the two paths would disagree about where output begins."""
    lines = normalise(text).split('\n')
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and lines[0].strip() == command.strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return '\n'.join(lines)


def render(outputs):
    """Build the capture file text. Mirrors capture.render()."""
    blocks = []
    for command in COMMANDS:
        blocks.append(format_delimiter(command))
        blocks.append(outputs[command].rstrip('\n'))
        blocks.append('')
    return '\n'.join(blocks)


def looks_paginated(text):
    """True if a pager prompt made it into the output, which means the capture
    is truncated. Checked here as well as in capture.py so the problem is
    reported while the session is still open and it can simply be re-run."""
    lowered = text.lower()
    return '--more--' in lowered.replace(' ', '') or '-- more --' in lowered


def read_prompt():
    """Return the device prompt from the current cursor line.

    This is the most fragile part of the script - everything else depends on
    knowing what to read up to. If a capture comes back empty, check this
    first: an unusual prompt, a banner still on screen, or a session sitting at
    a --More-- is what breaks it."""
    row = crt.Screen.CurrentRow
    column = crt.Screen.CurrentColumn - 1
    if column < 1:
        return ''
    return crt.Screen.Get(row, 1, row, column).strip()


def run_command(command, prompt):
    """Send one command and return its output, without echo or trailing prompt."""
    crt.Screen.Send(command + '\r')
    output = crt.Screen.ReadString(prompt, READ_TIMEOUT_SECONDS)
    if output is None:
        raise RuntimeError(
            "Timed out after {0}s waiting for the prompt after '{1}'.\n\n"
            'Nothing was written. The session may still be paging, or the '
            'prompt may have changed mid-command.'.format(READ_TIMEOUT_SECONDS, command))
    return strip_echo(output, command)


def main():
    if not crt.Session.Connected:
        crt.Dialog.MessageBox('Connect and log in to the switch first, then run this script.',
                              'Not connected')
        return

    crt.Screen.Synchronous = True
    try:
        prompt = read_prompt()
        if not prompt:
            crt.Dialog.MessageBox(
                'Could not read the device prompt from the current line.\n\n'
                'Press Enter in the session so the prompt is the last thing on '
                'screen, then run this script again.', 'No prompt found')
            return
        if prompt.endswith('>'):
            crt.Dialog.MessageBox(
                'This session is in user EXEC mode ({0}).\n\n'
                'show running-config needs privileged EXEC. Run "enable" first, '
                'then run this script again.'.format(prompt), 'Not in enable mode')
            return
        if not prompt.endswith('#'):
            crt.Dialog.MessageBox(
                'The prompt does not look like a Cisco EXEC prompt: "{0}"\n\n'
                'Press Enter in the session and try again.'.format(prompt),
                'Unexpected prompt')
            return

        hostname = prompt.rstrip('#').strip() or 'switch'

        # Paging off, or running-config comes back full of --More-- prompts and
        # backspace padding. Session-scoped, so nothing is left behind.
        run_command('terminal length 0', prompt)

        outputs = {}
        for command in COMMANDS:
            outputs[command] = run_command(command, prompt)
            if not outputs[command].strip():
                crt.Dialog.MessageBox(
                    "'{0}' returned nothing.\n\nNothing was written - a command that "
                    'returns nothing is indistinguishable from a feature that is '
                    'switched off, and the audit refuses captures like that rather '
                    'than reporting against them.'.format(command), 'Empty output')
                return
            if looks_paginated(outputs[command]):
                crt.Dialog.MessageBox(
                    "'{0}' came back with a pager prompt, so its output is "
                    'truncated.\n\nNothing was written. Run "terminal length 0" by '
                    'hand and try again.'.format(command), 'Output truncated')
                return

        # The default is an absolute path in the user's home directory. A bare
        # filename resolves against SecureCRT's working directory - its own
        # install folder under Program Files - and the write dies with
        # Permission denied after a perfectly good capture (found on the first
        # real-terminal run, 2026-08-28, with all five commands captured).
        import os.path
        default_path = os.path.join(
            os.path.expanduser('~'),
            '{0}_{1}.capture'.format(hostname, _timestamp()))
        path = crt.Dialog.Prompt('Write the capture to:', 'Save capture', default_path)
        if not path:
            return
        if not os.path.isabs(path):
            path = os.path.join(os.path.expanduser('~'), path)

        try:
            with open(path, 'w', encoding='utf-8') as capture_file:
                capture_file.write(render(outputs))
        except OSError as error:
            crt.Dialog.MessageBox(
                'Could not write {0}:\n{1}\n\nThe capture is intact in memory but '
                'was not saved. Run the script again and give a full path to a '
                'folder you can write to.'.format(path, error), 'Capture failed')
            return

        crt.Dialog.MessageBox(
            'Captured {0} commands from {1}.\n\nWritten to:\n{2}\n\nAudit it with:\n'
            'python3 l2_stig_audit.py {1} --from-capture <file>'
            .format(len(COMMANDS), hostname, path), 'Capture complete')
    except Exception as error:  # surfaced in a dialog; SecureCRT hides tracebacks
        crt.Dialog.MessageBox('{0}\n\nNo capture was written.'.format(error), 'Capture failed')
    finally:
        crt.Screen.Synchronous = False


def _timestamp():
    import time
    return time.strftime('%Y%m%d_%H%M%S')


# `crt` is supplied by SecureCRT at runtime, not imported. Declared here only so
# linters and IDEs stop flagging the references above as undefined; SecureCRT's
# own injection takes precedence when the script actually runs.
crt = globals().get('crt')

# SecureCRT injects `crt` into this script's globals before running it, so this
# is truthy there and None on a plain import - which is what lets the test suite
# import the module, substitute a stand-in for `crt`, and drive main() without a
# terminal anywhere in sight.
if crt is not None:
    main()
