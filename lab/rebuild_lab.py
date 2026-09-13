#!/usr/bin/env python
"""Rebuild the GNS3 lab from lab/topology.yaml.

Exists because the lab has been lost once already - the GNS3 VM was deleted on
2026-08-28 and reconstructing it by hand took an afternoon of one-off API calls
and console typing that lived nowhere afterwards. This script is that afternoon
written down: run it against an empty GNS3 server (with the disk images
imported - see below) and it produces the working lab; run it against the
live lab and it verifies everything and changes nothing, which is also how the
script itself is tested without deleting anything.

    python3 lab/rebuild_lab.py            # build/converge, then verify
    python3 lab/rebuild_lab.py --verify   # verify only, touch nothing

Each step checks before it acts, so a re-run converges instead of duplicating:
existing projects/nodes/links are reused, provisioning steps that already
happened are skipped, and the switch config push is idempotent IOS commands.

What it cannot do: recreate disk images. The IOSvL2 qcow2 and the automation
container's docker image must be imported into GNS3 first (the script checks
the templates exist and stops with a clear message if not), and VMware's VMnet8
must be the default NAT network. Device credentials are prompted (or
SSH_USERNAME/SSH_PASSWORD, same convention as every other script here) - on a
factory-fresh switch they become the local admin account; on an already-built
switch they must be its existing credentials.

Runs from the Windows side (or anywhere that reaches the GNS3 server): needs
only pyyaml beyond the standard library - deliberately not netmiko, since the
switch may not speak SSH until this script finishes configuring it. All device
interaction goes over the GNS3 console (telnet), which exists from boot.
"""

import argparse
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from getpass import getpass

import yaml

TOPOLOGY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'topology.yaml')


def load_topology(path=None):
    with open(path or TOPOLOGY_PATH, encoding='utf-8') as f:
        return yaml.safe_load(f)


class RebuildError(Exception):
    """A step failed in a way the operator has to look at. Raised with a
    message that says what to check, because half of these fire on a fresh
    GNS3 install where the fix is an import or a VMware setting."""


# --------------------------------------------------------------------------
# GNS3 REST API (v2), stdlib only
# --------------------------------------------------------------------------

class Gns3:
    def __init__(self, server):
        self.base = server.rstrip('/') + '/v2'

    def _call(self, method, path, body=None):
        request = urllib.request.Request(
            self.base + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Content-Type': 'application/json'},
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                text = response.read().decode()
                return json.loads(text) if text.strip() else None
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors='replace')[:300]
            raise RebuildError(f'{method} {path} -> HTTP {error.code}: {detail}')
        except urllib.error.URLError as error:
            raise RebuildError(
                f'Cannot reach the GNS3 server at {self.base}: {error.reason}\n'
                'Is the GNS3 VM running, and does lab/topology.yaml carry its address?')

    def get(self, path):
        return self._call('GET', path)

    def post(self, path, body=None):
        return self._call('POST', path, body if body is not None else {})

    def put(self, path, body):
        return self._call('PUT', path, body)

    # -- node file API: raw text, not JSON --------------------------------
    def write_node_file(self, project_id, node_id, path, content):
        request = urllib.request.Request(
            f'{self.base}/projects/{project_id}/nodes/{node_id}/files/{path}',
            data=content.encode(), headers={'Content-Type': 'text/plain'}, method='POST')
        try:
            urllib.request.urlopen(request, timeout=30).read()
        except urllib.error.HTTPError as error:
            raise RebuildError(f'writing node file {path} -> HTTP {error.code}')


# --------------------------------------------------------------------------
# GNS3 console (telnet) driver - same negotiation handling proven during the
# 2026-08-28 rebuild. Consoles exist from the moment a node starts, which is
# why all device interaction runs through them rather than SSH.
# --------------------------------------------------------------------------

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240


class Console:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=10)

    def close(self):
        self.sock.close()

    def _strip_telnet(self, data):
        out, i = bytearray(), 0
        while i < len(data):
            byte = data[i]
            if byte != IAC:
                out.append(byte)
                i += 1
                continue
            if i + 1 >= len(data):
                break
            command = data[i + 1]
            if command in (DO, DONT, WILL, WONT):
                if i + 2 >= len(data):
                    break
                reply = WONT if command == DO else (DONT if command == WILL else None)
                if reply is not None:
                    try:
                        self.sock.sendall(bytes([IAC, reply, data[i + 2]]))
                    except OSError:
                        pass
                i += 3
            elif command == SB:
                end = data.find(bytes([IAC, SE]), i)
                i = len(data) if end == -1 else end + 2
            else:
                i += 2
        return bytes(out)

    def read(self, quiet_seconds):
        """Read until the console stays quiet for quiet_seconds."""
        self.sock.settimeout(quiet_seconds)
        chunks = []
        while True:
            try:
                data = self.sock.recv(65535)
            except (socket.timeout, OSError):
                break
            if not data:
                break
            chunks.append(self._strip_telnet(data))
        return b''.join(chunks).decode('utf-8', 'replace')

    def send(self, line):
        self.sock.sendall(line.encode() + b'\r')

    def expect(self, pattern, timeout, poke=False):
        """Read until `pattern` appears; optionally send bare returns each
        cycle, which is how a booting IOS console is coaxed into showing
        whether it is ready. Returns the accumulated text, or None."""
        deadline, seen = time.time() + timeout, ''
        while time.time() < deadline:
            seen += self.read(1.5)
            if re.search(pattern, seen, re.I | re.M):
                return seen
            if poke:
                self.send('')
        return None

    def run(self, command, quiet_seconds=3.0):
        self.send(command)
        time.sleep(0.3)
        return self.read(quiet_seconds)


# --------------------------------------------------------------------------
# Steps
# --------------------------------------------------------------------------

def step(message):
    print(f'\n=== {message}')


def ok(message):
    print(f'    {message}')


def get_device_credentials():
    """Same convention as netauto.get_credentials(), without importing netauto
    (which imports netmiko, which this script deliberately does not need)."""
    username = os.environ.get('SSH_USERNAME') or input('Device username to configure/use: ')
    password = os.environ.get('SSH_PASSWORD') or getpass('Device password: ')
    return username, password


def preflight(api, topo):
    step('preflight: server, templates, SSH public key')
    version = api.get('/version')
    ok(f'GNS3 server {version["version"]} at {topo["gns3"]["server"]}')

    templates = {t['name']: t for t in api.get('/templates')}
    resolved = {}
    for role, name in topo['templates'].items():
        if name not in templates:
            raise RebuildError(
                f'Template "{name}" is not on this GNS3 server.\n'
                'Disk images cannot be recreated by this script - import the '
                'IOSvL2 qcow2 / docker image and recreate the template first.')
        resolved[role] = templates[name]
        ok(f'template "{name}" present ({templates[name]["template_type"]})')

    key_path = os.path.expanduser(topo['automation_host']['ssh_public_key'])
    if not os.path.exists(key_path):
        raise RebuildError(
            f'SSH public key not found: {key_path}\n'
            "Generate one (ssh-keygen -t ed25519 -f ~/.ssh/netauto_ed25519) or "
            'point automation_host.ssh_public_key at an existing .pub file.')
    with open(key_path, encoding='utf-8') as f:
        public_key = f.read().strip()
    ok(f'SSH public key loaded from {key_path}')
    return resolved, public_key


def ensure_project(api, topo):
    step(f'project "{topo["gns3"]["project"]}"')
    wanted = topo['gns3']['project']
    for project in api.get('/projects'):
        if project['name'] == wanted:
            if project['status'] != 'opened':
                api.post(f'/projects/{project["project_id"]}/open')
            ok(f'reusing existing project ({project["project_id"]})')
            return project['project_id']
    project = api.post('/projects', {'name': wanted})
    ok(f'created ({project["project_id"]})')
    return project['project_id']


def ensure_nodes(api, project_id, topo, templates):
    step('nodes')
    existing = {n['name']: n for n in api.get(f'/projects/{project_id}/nodes')}
    nodes = {}
    for name, spec in topo['nodes'].items():
        if name in existing:
            ok(f'{name}: exists ({existing[name]["status"]})')
            nodes[name] = existing[name]
        elif 'builtin' in spec:
            node = api.post(f'/projects/{project_id}/nodes', {
                'name': name, 'node_type': spec['builtin'], 'compute_id': 'local',
                'x': spec.get('x', 0), 'y': spec.get('y', 0)})
            ok(f'{name}: created ({spec["builtin"]})')
            nodes[name] = node
        else:
            template = templates[spec['template']]
            node = api.post(
                f'/projects/{project_id}/templates/{template["template_id"]}',
                {'x': spec.get('x', 0), 'y': spec.get('y', 0), 'compute_id': 'local'})
            if node['name'] != name:
                node = api.put(f'/projects/{project_id}/nodes/{node["node_id"]}',
                               {'name': name})
            ok(f'{name}: created from template "{template["name"]}"')
            nodes[name] = node

        adapters = spec.get('adapters')
        current = nodes[name].get('properties', {}).get('adapters')
        if adapters and current != adapters:
            # Adapter count only changes while the node is stopped; a link
            # made against the old count leaves a stale bridge (learned the
            # hard way - S1 showed packets out and none in).
            if nodes[name]['status'] != 'stopped':
                api.post(f'/projects/{project_id}/nodes/{nodes[name]["node_id"]}/stop')
                time.sleep(3)
            nodes[name] = api.put(
                f'/projects/{project_id}/nodes/{nodes[name]["node_id"]}',
                {'properties': {'adapters': adapters}})
            ok(f'{name}: adapters set to {adapters}')
    return nodes


def ensure_links(api, project_id, topo, nodes):
    step('links')
    existing = api.get(f'/projects/{project_id}/links')
    have = set()
    for link in existing:
        ends = frozenset((n['node_id'], n['adapter_number'], n['port_number'])
                         for n in link['nodes'])
        have.add(ends)
    for spec in topo['links']:
        ends = frozenset((nodes[name]['node_id'], adapter, port)
                         for name, adapter, port in spec)
        label = ' <-> '.join(f'{name} a{adapter}/p{port}' for name, adapter, port in spec)
        if ends in have:
            ok(f'exists: {label}')
            continue
        api.post(f'/projects/{project_id}/links', {'nodes': [
            {'node_id': nodes[name]['node_id'], 'adapter_number': adapter,
             'port_number': port} for name, adapter, port in spec]})
        ok(f'created: {label}')


def container_interfaces_file(host_cfg):
    return f"""# Managed by lab/rebuild_lab.py - edits here are overwritten on rebuild.

# eth0 - lab management segment. Matches inventory.yaml's automation_host.
auto eth0
iface eth0 inet static
\taddress {host_cfg['lab_ip']}
\tnetmask {host_cfg['lab_netmask']}

# eth1 - VMware VMnet8 (NAT). Static so the PyCharm/SSH target never moves.
# The post-up hooks run from GNS3's init on every container start, which is
# what makes sshd survive restarts - there is no systemd in this container.
auto eth1
iface eth1 inet static
\taddress {host_cfg['vmnet_ip']}
\tnetmask {host_cfg['vmnet_netmask']}
\tgateway {host_cfg['vmnet_gateway']}
\tpost-up echo 'nameserver {host_cfg['vmnet_gateway']}' > /etc/resolv.conf || true
\tpost-up mkdir -p /run/sshd && /usr/sbin/sshd
"""


def provision_container(api, project_id, topo, nodes, public_key, gns3_host):
    step('automation host')
    node = nodes['NetworkAutomation-1']
    host_cfg = topo['automation_host']

    api.write_node_file(project_id, node['node_id'], 'etc/network/interfaces',
                        container_interfaces_file(host_cfg))
    ok('wrote /etc/network/interfaces')

    if node['status'] != 'started':
        api.post(f'/projects/{project_id}/nodes/{node["node_id"]}/start')
        time.sleep(10)
        ok('started')

    console = Console(gns3_host, node['console'])
    try:
        console.send('')
        if console.expect(r'#\s*$', timeout=20, poke=True) is None:
            raise RebuildError('No shell prompt on the container console.')

        # Each block checks its own marker first, so re-runs skip completed
        # work. Everything is driven through the console because the GNS3
        # file API 403s outside a node's whitelisted paths, and because SSH
        # into the container is one of the things being set up.
        console.run(f"mkdir -p /root/.ssh && chmod 700 /root/.ssh && "
                    f"grep -qF '{public_key}' /root/.ssh/authorized_keys 2>/dev/null || "
                    f"echo '{public_key}' >> /root/.ssh/authorized_keys")
        console.run('chmod 600 /root/.ssh/authorized_keys')
        ok('authorized_keys in place')

        # Markers are quote-split ('SSHD_''NO') so the marker string never
        # appears verbatim in the echoed command line - checking the raw
        # console output would otherwise match the echo and always "detect"
        # the miss, which is exactly the bug this replaced.
        out = console.run("ls /usr/sbin/sshd > /dev/null 2>&1 && echo SSHD_''YES || echo SSHD_''NO")
        if 'SSHD_NO' in out:
            ok('installing openssh-server (a few minutes; needs VMnet8 internet)...')
            # apt-get update exits nonzero on this image (an unrelated repo
            # with a bad GPG key) while the Ubuntu lists still refresh - so
            # update and install are deliberately not && -chained.
            console.run('apt-get update > /tmp/apt.log 2>&1', quiet_seconds=5)
            console.send('DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server '
                         '> /tmp/sshd_install.log 2>&1; echo APT_DONE_RC=$?')
            got = console.expect(r'APT_DONE_RC=\d+', timeout=420)
            if got is None or 'APT_DONE_RC=0' not in got:
                raise RebuildError(
                    'openssh-server install did not finish cleanly - check '
                    '/tmp/sshd_install.log on the container console.')
        console.run("sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config")
        console.run('ssh-keygen -A > /dev/null 2>&1; mkdir -p /run/sshd; '
                    'pgrep -x sshd > /dev/null || /usr/sbin/sshd')
        ok('sshd configured and running (key-only root login)')

        # git is not in this container image. The original automation host had
        # it because somebody installed it by hand once, which is exactly the
        # kind of undocumented step that made the lab unrebuildable the first
        # time - so it is checked and installed here like everything else.
        out = console.run("command -v git > /dev/null 2>&1 && echo GIT_''YES || echo GIT_''NO")
        if 'GIT_NO' in out:
            ok('installing git (needs VMnet8 internet)...')
            console.run('apt-get update > /tmp/apt.log 2>&1', quiet_seconds=5)
            console.send('DEBIAN_FRONTEND=noninteractive apt-get install -y git '
                         '> /tmp/git_install.log 2>&1; echo GIT_DONE_RC=$?')
            got = console.expect(r'GIT_DONE_RC=\d+', timeout=420)
            if got is None or 'GIT_DONE_RC=0' not in got:
                raise RebuildError(
                    'git install did not finish cleanly - check '
                    '/tmp/git_install.log on the container console.')
            ok('git installed')

        out = console.run(f"ls -d {host_cfg['repo_path']}/.git > /dev/null 2>&1 "
                          "&& echo REPO_''YES || echo REPO_''NO")
        if 'REPO_NO' in out:
            ok('cloning the repo (needs VMnet8 internet)...')
            console.send(f'git clone {host_cfg["repo_url"]} {host_cfg["repo_path"]} '
                         '> /tmp/clone.log 2>&1; echo CLONE_RC=$?')
            got = console.expect(r'CLONE_RC=\d+', timeout=300)
            if got is None or 'CLONE_RC=0' not in got:
                raise RebuildError('git clone failed - check /tmp/clone.log on the console.')
        else:
            ok('repo already present')

        console.send("python3 -c 'import netmiko' 2>/dev/null && echo PKGS_''YES || echo PKGS_''NO")
        got = console.expect(r'PKGS_(YES|NO)\b', timeout=60)
        if got and 'PKGS_NO' in got:
            ok('installing python packages (a few minutes)...')
            console.send('python3 -m pip install --upgrade pip > /tmp/pip.log 2>&1; '
                         f'python3 -m pip install -r {host_cfg["repo_path"]}/requirements.txt '
                         '>> /tmp/pip.log 2>&1; echo PIP_RC=$?')
            got = console.expect(r'PIP_RC=\d+', timeout=600)
            if got is None or 'PIP_RC=0' not in got:
                raise RebuildError('pip install failed - check /tmp/pip.log on the console.')
        ok('netmiko importable')

        # Re-apply addressing in case the interfaces file changed this run.
        console.run('ifdown eth0 2>/dev/null; ifup eth0 2>/dev/null')
        console.run('ifdown eth1 2>/dev/null; ifup eth1 2>/dev/null', quiet_seconds=5)
        out = console.run('hostname -I')
        if host_cfg['lab_ip'] not in out or host_cfg['vmnet_ip'] not in out:
            raise RebuildError(f'container addressing wrong, hostname -I said: {out.strip()}')
        ok(f'addresses up: {host_cfg["lab_ip"]} (lab), {host_cfg["vmnet_ip"]} (VMnet8)')
    finally:
        console.close()


SWITCH_CONFIG_TEMPLATE = [
    'hostname {hostname}',
    'no ip domain-lookup',
    'ip domain-name {domain}',
    'username {username} privilege 15 secret {password}',
    'enable secret {password}',
    'vlan {mgmt_vlan}',
    'name {mgmt_vlan_name}',
    'exit',
    'interface {uplink_interface}',
    'switchport mode access',
    'switchport access vlan {mgmt_vlan}',
    'no shutdown',
    'exit',
    'interface Vlan{mgmt_vlan}',
    'ip address {mgmt_ip} {mgmt_netmask}',
    'no shutdown',
    'exit',
    'ip ssh version 2',
    'line vty 0 4',
    # 'login local' is inserted here at runtime only when aaa new-model is
    # absent - see configure_switch(). With AAA active (this repo's own
    # harden enables it) the command is invalid on vty lines and unnecessary:
    # the AAA default method list governs login instead. Found live on the
    # first converge run against the already-hardened S1.
    'transport input ssh',
    'exec-timeout 5 0',
    'exit',
]


def ios_reach_privileged_exec(console, username, password):
    """Drive an IOS console from whatever state it is in to privileged EXEC.

    Extracted from configure_switch so the multi-vendor lab's routers and
    switches get the same proven path rather than a second implementation of
    it - this is the part with the scar tissue, and two copies would drift.
    """
    # The gate accepts config-mode prompts too ((config)#, (config-line)#
    # ...) - a previous run that died mid-config leaves the shared console
    # sitting at one, and a gate that only knows bare >/# pokes at it for
    # the full timeout without ever recognising it. The state loop below
    # is what backs out of config mode; the gate just has to let it run.
    if console.expect(
            r'(initial configuration dialog|Press RETURN|Username:|Password:'
            r'|[\r\n][\w.-]+(\([\w-]+\))?[>#])',
            timeout=420, poke=True) is None:
        raise RebuildError('console never reached a prompt - still booting?')

    # Reach privileged EXEC via a state loop: drain whatever is stale in
    # the buffer, poke, classify only the freshest line, and act on it.
    # A GNS3 console is one shared TTY - a previous session may have left
    # it mid-login, mid-config, or with queued garbage, and matching
    # against accumulated history (the first version of this) meant
    # confidently typing 'enable' into a Username: prompt. The states:
    # setup dialog (factory-fresh), Username: (this repo's own AAA harden
    # puts login on the console line), bare > or #, or a config prompt.
    console.read(1.5)  # discard stale buffer
    for _ in range(15):
        console.send('')
        text = console.read(2.0)
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        last = lines[-1] if lines else ''
        if re.search(r'initial configuration dialog', text, re.I):
            console.send('no')
        elif re.search(r'\[confirm\]|\[yes/no\]', last, re.I):
            console.send('')
        elif re.search(r'Username:$', last):
            console.send(username)
            if console.expect(r'Password:', timeout=15) is None:
                raise RebuildError('console login: no Password: prompt after username')
            console.send(password)
        elif re.search(r'Password:$', last):
            console.send(password)  # a stale enable/login password prompt
        elif re.search(r'\(config[\w-]*\)#$', last):
            console.send('end')
        elif last.endswith('#'):
            return
        elif last.endswith('>'):
            console.send('enable')
            got = console.expect(r'(Password:|[\r\n][\w.-]+#[ \t]*\r?$)', timeout=15) or ''
            if got.rstrip().endswith('Password:'):
                console.send(password)
        # anything else (banner text, syslog burst): loop and re-poke
    raise RebuildError(
        'could not reach privileged EXEC on the console - wrong device '
        'credentials, or the console is wedged (connect to it manually and look)')


def configure_switch(api, project_id, topo, nodes, gns3_host, username, password):
    """Push the base config over the switch console, prompt-synchronized.

    Every command waits for the prompt to come back before the next is sent.
    The first version of this used quiet-window reads instead and desynced
    exactly once - which was enough: a late echo made the is-SSH-enabled
    check miss, keys were regenerated for nothing, and 'write memory' was
    typed into a console that was still mid-keygen.

    The connect path handles four different console states, because a lab
    switch is not always factory-fresh: the setup dialog (fresh boot), a bare
    prompt (never hardened), and a Username: login (this project's own AAA
    harden puts login authentication on the console line, so the second
    rebuild against a hardened switch lands here - the state that exposed the
    quiet-window version)."""
    step('switch base config')
    node = nodes['S1']
    switch = topo['switch']
    # \r? before $: console lines end \r\n, and re.M's $ only matches before
    # \n - without it the prompt only matches when it happens to be the last
    # byte received, and any async syslog line landing after it (the archive
    # config-logging this repo's own harden enables logs every command) makes
    # a returned prompt invisible. Found live: 'no ip domain-lookup' timed out
    # with 'S1(config)#\r\n<CFGLOG line>' sitting right there in the buffer.
    prompt = r'[\r\n][\w.-]+(\((?:config[\w-]*)\))?#[ \t]*\r?$'

    if node['status'] != 'started':
        api.post(f'/projects/{project_id}/nodes/{node["node_id"]}/start')
        ok('booting (IOSvL2 takes several minutes)...')

    console = Console(gns3_host, node['console'])

    def run_synced(command, timeout=30, error_ok=False):
        console.send(command)
        seen = console.expect(prompt, timeout)
        if seen is None:
            raise RebuildError(f'no prompt back after {command!r} within {timeout}s')
        if not error_ok and ('% Invalid' in seen or '% Incomplete' in seen):
            raise RebuildError(f'switch rejected: {command!r}')
        return seen

    try:
        ios_reach_privileged_exec(console, username, password)
        ok('console responsive, privileged EXEC')

        run_synced('terminal length 0')

        # RSA keys: checked from EXEC before config mode, and skipped when SSH
        # already reports enabled - regeneration invalidates known_hosts
        # everywhere for no benefit.
        needs_keys = 'SSH Enabled' not in run_synced('show ip ssh', timeout=20, error_ok=True)

        # Line-by-line check rather than a substring: the echoed command below
        # contains 'aaa new-model' itself, so a naive `in` test would always
        # be true (same echo trap as the container-side markers).
        aaa_out = run_synced('show running-config | include ^aaa new-model',
                             timeout=20, error_ok=True)
        aaa_active = any(line.strip() == 'aaa new-model' for line in aaa_out.splitlines())

        config_lines = []
        for line in SWITCH_CONFIG_TEMPLATE:
            config_lines.append(line.format(username=username, password=password, **switch))
            if line == 'line vty 0 4' and not aaa_active:
                config_lines.append('login local')

        run_synced('configure terminal')
        for command in config_lines:
            run_synced(command)
        ok(f'base config pushed ({len(config_lines)} lines'
           f'{", AAA active so login stays with AAA" if aaa_active else ""})')

        if needs_keys:
            ok('generating RSA keys (slow)...')
            console.send('crypto key generate rsa modulus 2048')
            got = console.expect(r'(\[OK\]|Replace them|\[yes/no\])', timeout=240)
            if got is None:
                raise RebuildError('RSA key generation produced no output')
            if re.search(r'Replace them|\[yes/no\]', got, re.I):
                console.send('yes')
                console.expect(r'\[OK\]', timeout=240)
            console.expect(prompt, timeout=60, poke=True)
        run_synced('end')

        run_synced('write memory', timeout=90)
        # Trust the startup-config, not the [OK] banner - the banner can
        # interleave with config-change syslog lines.
        saved = run_synced('show startup-config | include ^hostname', timeout=30, error_ok=True)
        if f'hostname {switch["hostname"]}' not in saved:
            raise RebuildError('startup-config does not carry the pushed hostname - save failed?')
        ok('saved to startup-config (verified by reading it back)')
    finally:
        console.close()


def start_nodes(api, project_id, nodes, names):
    """Start everything first so the images boot concurrently.

    Configuring device-by-device would otherwise serialise the boots, and an
    IOSv takes minutes to reach a console prompt - six of them in sequence is
    most of an hour spent waiting rather than working.
    """
    step('starting nodes')
    for name in names:
        node = nodes[name]
        if node['status'] == 'started':
            ok(f'{name}: already running')
            continue
        api.post(f'/projects/{project_id}/nodes/{node["node_id"]}/start')
        ok(f'{name}: started')


def configure_ios_device(api, project_id, name, node, spec, gns3_host,
                         username, password):
    """Push one device's config lines over its console, prompt-synchronized.

    The lines come from the topology file, not from this function - see the
    devices: section there. This only knows how to type them safely.
    """
    step(f'{name}: base config')
    prompt = r'[\r\n][\w.-]+(\((?:config[\w-]*)\))?#[ \t]*\r?$'
    console = Console(gns3_host, node['console'])

    def run_synced(command, timeout=30, error_ok=False):
        console.send(command)
        seen = console.expect(prompt, timeout)
        if seen is None:
            raise RebuildError(f'{name}: no prompt back after {command!r} within {timeout}s')
        if not error_ok and ('% Invalid' in seen or '% Incomplete' in seen):
            raise RebuildError(f'{name} rejected: {command!r}')
        return seen

    try:
        ios_reach_privileged_exec(console, username, password)
        ok(f'{name}: console responsive, privileged EXEC')
        run_synced('terminal length 0')

        # Skip key generation when SSH is already up - regenerating
        # invalidates known_hosts everywhere for no benefit.
        needs_keys = 'SSH Enabled' not in run_synced('show ip ssh', timeout=20,
                                                     error_ok=True)

        run_synced('configure terminal')
        for line in spec['config']:
            # 90s, not the 30s a config line normally needs: creating the first
            # VLAN makes IOSvL2 write vlan.dat to flash, and on this emulated
            # disk that took longer than 30s - the run died on 'name USERS'
            # with the switch sitting perfectly healthy at (config-vlan)#.
            # A generous ceiling costs nothing on the lines that are instant.
            run_synced(line.format(username=username, password=password), timeout=90)
        ok(f'{name}: {len(spec["config"])} config lines pushed')

        if needs_keys:
            ok(f'{name}: generating RSA keys (slow)...')
            console.send('crypto key generate rsa modulus 2048')
            got = console.expect(r'(\[OK\]|Replace them|\[yes/no\])', timeout=240)
            if got is None:
                raise RebuildError(f'{name}: RSA key generation produced no output')
            if re.search(r'Replace them|\[yes/no\]', got, re.I):
                console.send('yes')
                console.expect(r'\[OK\]', timeout=240)
            console.expect(prompt, timeout=60, poke=True)
        run_synced('end')

        run_synced('write memory', timeout=90)
        # Trust the startup-config, not the [OK] banner - the banner can
        # interleave with config-change syslog lines.
        saved = run_synced('show startup-config | include ^hostname', timeout=30,
                           error_ok=True)
        if f'hostname {name}' not in saved:
            raise RebuildError(f'{name}: startup-config does not carry the hostname - save failed?')
        ok(f'{name}: saved to startup-config (verified by reading it back)')
    finally:
        console.close()


def junos_reach_cli(console, password):
    """Drive a Junos console from whatever state it is in to operational CLI.

    Same idea as ios_reach_privileged_exec, different states. A vJunos that has
    never been configured logs in as root with NO password and lands in a
    FreeBSD shell; once this script has run once, root HAS a password and the
    same console lands in the CLI instead. Both have to work, because the
    second run of a rebuild is the one that matters.
    """
    # Deadline, not an iteration count. The first version allowed 20 pokes -
    # about 40 seconds - which is nothing against a vJunos boot: the image
    # brings up a Linux wrapper, then Junos inside a nested QEMU, and prints
    # plenty of '#'-terminated chatter on the way that looks like a prompt.
    # It gave up every time on a switch that was simply still booting.
    deadline = time.time() + 1200
    console.read(1.5)  # discard stale buffer
    while time.time() < deadline:
        console.send('')
        text = console.read(2.0)
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        # Scan the last few lines, not only the final one: the ZTP DHCP client
        # prints a status line every couple of seconds, so on a fresh vJunos
        # the true last line is almost always chatter and a strict
        # "classify lines[-1]" loop never sees the prompt at all.
        prompt_line = next(
            (line for line in reversed(lines[-6:])
             if re.search(r'(login:|[%>#]$)', line)), '')
        last = prompt_line or (lines[-1] if lines else '')
        # Escape the pager FIRST. Junos pages any long output with
        # '---(more NN%)---', and inside the pager single keystrokes are
        # commands: 's' means "save to a file", so a 'set ...' typed at a
        # pager is read as save-to-file named "et ...". Every command after
        # that vanishes into the pager and the device looks wedged while it
        # is simply waiting for a keypress.
        if '(more' in text or 'Filename:' in text:
            console.send('q')
            continue
        if re.search(r'login:$', last):
            console.send('root')
            got = console.expect(r'(Password:|[%#>]\s*$)', timeout=30) or ''
            if 'Password:' in got:
                console.send(password)
        elif re.search(r'Password:$', last):
            console.send(password)
        elif last.endswith('>'):
            return                      # operational CLI - where we want to be
        elif re.search(r'^root@[\w.-]*:.*#$', last) or last.endswith('%'):
            console.send('cli')         # FreeBSD shell -> CLI
        elif last.endswith('#'):
            console.send('exit')        # configuration mode -> operational
        # anything else (boot chatter, DHCP client noise): loop and re-poke
    raise RebuildError(
        'could not reach the Junos operational CLI within 20 minutes - connect '
        'to the console manually and look at what state it is in')


def junos_wait_ready(console, password, timeout=1800):
    """Wait until the CLI is stable enough to configure, not merely present.

    30 minutes, not the 15 this used to allow, measured on this host. A FIRST
    boot on a fresh disk overlay took about 16 minutes to a stable CLI on JSW1,
    and more than 16 on JSW2 - which gave up at exactly 15 minutes, while
    `show version` was answering on its console a few seconds later
    (2026-09-13). A bootstrap started alongside the node, which is the normal
    rebuild, spends almost all of its time in here.

    A vJunos reaches a login prompt minutes before it is actually usable: mgd
    is still starting and the PFE is still printing tnp_hello_tx chatter onto
    the console. Configuring in that window fails in a specific and confusing
    way - the CLI session dies with 'remote side unexpectedly closed
    connection' and drops to the FreeBSD shell, where the next set-command is
    typed into sh and simply hangs.

    Readiness is defined as 'show version' answering cleanly twice in a row.
    Twice, because it answers once during the unstable window too.
    """
    deadline = time.time() + timeout
    clean_runs = 0
    while time.time() < deadline:
        junos_reach_cli(console, password)
        # Disable paging BEFORE running anything that can page. Doing it the
        # other way round is what put the console into the pager in the first
        # place, where the command meant to disable paging was itself eaten.
        console.run('set cli screen-length 0', quiet_seconds=3)
        out = console.run('show version', quiet_seconds=6)
        if 'Junos:' in out and 'closed connection' not in out:
            clean_runs += 1
            if clean_runs >= 2:
                ok('CLI stable (show version answered cleanly twice)')
                return
        else:
            clean_runs = 0
        time.sleep(15)
    raise RebuildError('Junos CLI never became stable enough to configure')


# Junos echoes the command then returns a prompt ending in > or #.
#
# NOT anchored to end-of-buffer, unlike the IOS prompt. A freshly booted vJunos
# whose fxp0 has no DHCP server prints
#   Auto Image Upgrade: DHCP INET6 Client State Reset : fxp0.0
# every couple of seconds forever, so there is almost always chatter sitting
# after the prompt and an anchored match never fires - the switch looks hung
# while it is sitting there perfectly idle. Accepting a prompt followed by a
# newline is what makes this work; `delete chassis auto-image-upgrade` in the
# config then stops the noise for good.
#
# \r*, not \r?. While that chatter is running, Junos redraws the prompt line:
# it pads it with spaces and ends it with THREE carriage returns, 'root#' +
# spaces + '\r\r\r\n'. A single optional \r never matches that, so the prompt
# sat in the buffer unrecognised and the run died on "no prompt back after
# 'set system domain-name lab.local' within 60s" (2026-09-13). The first two
# commands only passed because their prompt happened to be the last byte
# received before the chatter arrived. tests/test_junos_console_prompt.py holds
# the real bytes.
JUNOS_CLI_PROMPT = r'[\r\n][\w.-]*@?[\w.-]*[>#][ \t]*\r*(\n|$)'


def configure_junos_device(name, node, spec, gns3_host, username, password):
    """Push one Junos device's set-commands over its console and commit.

    Scope matches the IOS devices: enough that Ansible can reach it. On Junos
    that specifically means `set system services netconf ssh` - every path this
    project has into a Junos box speaks NETCONF, and without it SSH to the CLI
    still works, which makes the failure look like bad credentials.
    """
    step(f'{name}: base config')
    console = Console(gns3_host, node['console'])
    cli_prompt = JUNOS_CLI_PROMPT

    def run_synced(command, timeout=60):
        console.send(command)
        seen = console.expect(cli_prompt, timeout)
        if seen is None:
            raise RebuildError(f'{name}: no prompt back after {command!r} within {timeout}s')
        # The CLI dying mid-config demotes the console to the FreeBSD shell,
        # whose prompt also ends in '#'. Without this check the next command is
        # typed into sh, which is how a run ends up hung on a healthy switch.
        if 'closed connection' in seen or re.search(r'root@[\w.-]*:~\s*#\s*$', seen):
            raise RebuildError(
                f'{name}: the CLI session dropped to the shell while running '
                f'{command!r} - the device was not ready to be configured')
        for bad in ('syntax error', 'unknown command', 'error:'):
            if bad in seen.lower():
                raise RebuildError(f'{name} rejected: {command!r}\n{seen.strip()[-200:]}')
        return seen

    try:
        junos_wait_ready(console, password)   # also disables paging
        ok(f'{name}: console responsive, operational CLI')
        run_synced('configure', timeout=60)

        for line in spec['config']:
            command = line.format(username=username, password=password)
            if command.endswith('plain-text-password'):
                # The one interactive command in the set. Junos will not take a
                # password as an argument here, and the encrypted-password form
                # needs a crypt hash this script has no portable way to make
                # (python's crypt module is gone as of 3.13), so the prompts
                # are answered instead.
                console.send(command)
                for expect_prompt in (r'New password:', r'Retype new password:'):
                    if console.expect(expect_prompt, timeout=30) is None:
                        raise RebuildError(f'{name}: no {expect_prompt!r} prompt')
                    console.send(password)
                if console.expect(cli_prompt, timeout=30) is None:
                    raise RebuildError(f'{name}: console did not return after setting the password')
            else:
                run_synced(command)
        ok(f'{name}: {len(spec["config"])} set-commands applied')

        # commit check first: it validates without changing anything, so a bad
        # config fails here rather than half-applied on a device the script can
        # no longer reach.
        seen = run_synced('commit check', timeout=180)
        if 'configuration check succeeds' not in seen.lower():
            raise RebuildError(f'{name}: commit check did not succeed\n{seen.strip()[-300:]}')
        ok(f'{name}: commit check passed')

        seen = run_synced('commit and-quit', timeout=240)
        if 'commit complete' not in seen.lower():
            raise RebuildError(f'{name}: commit did not complete\n{seen.strip()[-300:]}')
        ok(f'{name}: committed')
    finally:
        console.close()


def configure_vpcs(name, node, spec, gns3_host):
    """Configure a VPCS endpoint. Its console is not IOS - no enable, no
    config mode, and the prompt is the node name followed by '>'."""
    step(f'{name}: endpoint config')
    console = Console(gns3_host, node['console'])
    try:
        if console.expect(r'>\s*$', timeout=60, poke=True) is None:
            raise RebuildError(f'{name}: VPCS console never showed a prompt')
        for line in spec['config']:
            console.send(line)
            if console.expect(r'>\s*$', timeout=20) is None:
                raise RebuildError(f'{name}: no prompt back after {line!r}')
        out = console.run('show ip', quiet_seconds=3)
        ok(f'{name}: {" ".join(out.split())[:120]}')
    finally:
        console.close()


def configure_devices(api, project_id, topo, nodes, gns3_host, username, password,
                      only=None):
    """Configure every device in the topology's devices: section.

    `only` narrows it to named devices. Useful because the slow devices are
    slow in a way the fast ones are not: re-pushing four Cisco boxes to retry
    one vJunos costs ten minutes of nothing, every attempt.
    """
    for name, spec in topo['devices'].items():
        if only and name not in only:
            continue
        node = nodes[name]
        platform = spec['platform']
        if platform == 'ios':
            configure_ios_device(api, project_id, name, node, spec, gns3_host,
                                 username, password)
        elif platform == 'junos':
            configure_junos_device(name, node, spec, gns3_host, username, password)
        elif platform == 'vpcs':
            configure_vpcs(name, node, spec, gns3_host)
        else:
            raise RebuildError(f'{name}: unknown platform {platform!r}')


def run_verify_pings(topo, nodes, gns3_host):
    """Run the topology's verify_pings over each source node's console.

    Driven over the console rather than over SSH so a failure here means the
    data path is broken, not that management or credentials are - those are
    separate problems and conflating them wastes the morning.
    """
    step('end-to-end pings')
    failures = []
    for check in topo.get('verify_pings', []):
        source, target = check['from'], check['to']
        node = nodes[source]
        platform = topo['devices'].get(source, {}).get('platform')
        console = Console(gns3_host, node['console'])
        try:
            console.send('')
            if platform == 'vpcs':
                console.expect(r'>\s*$', timeout=20, poke=True)
                console.run(f'ping {target} -c 1', quiet_seconds=5)   # prime ARP
                out = console.run(f'ping {target} -c 3', quiet_seconds=8)
                good = 'bytes from' in out
            elif platform == 'junos':
                console.expect(r'>\s*$', timeout=30, poke=True)
                console.run(f'ping {target} count 1', quiet_seconds=6)   # prime ARP
                out = console.run(f'ping {target} count 3', quiet_seconds=10)
                good = 'bytes from' in out and '100% packet loss' not in out
            elif platform == 'ios':
                console.expect(r'#\s*\r?$', timeout=20, poke=True)
                # Prime ARP first and assert on the second run. The first
                # packet to an unresolved neighbour is dropped while ARP
                # completes, so a cold 'repeat 3' reports 66% on a segment that
                # is perfectly healthy - which failed this check on the transit
                # link the first time it was cabled.
                console.run(f'ping {target} repeat 2', quiet_seconds=8)
                out = console.run(f'ping {target} repeat 3', quiet_seconds=10)
                good = 'Success rate is 100' in out
            else:
                # The automation container: a plain Linux shell.
                console.expect(r'#\s*$', timeout=20, poke=True)
                out = console.run(f'ping -c2 -W3 {target}', quiet_seconds=8)
                good = ' 0% packet loss' in out
            if good:
                ok(f'{source} -> {target} ({check["why"]})')
            else:
                failures.append(f'{source} -> {target}: {check["why"]}\n      '
                                f'{" ".join(out.split())[-200:]}')
        finally:
            console.close()
    return failures


def verify(topo, nodes, gns3_host):
    step('verify')
    host_cfg = topo['automation_host']
    failures = []

    # 1. SSH port open on the container's VMnet8 address, from here.
    try:
        socket.create_connection((host_cfg['vmnet_ip'], 22), timeout=8).close()
        ok(f'container SSH reachable at {host_cfg["vmnet_ip"]}:22')
    except OSError as error:
        failures.append(f'container SSH unreachable at {host_cfg["vmnet_ip"]}:22 ({error})')

    # 2. Container -> switch, over the lab segment - the path every audit and
    #    harden script depends on. Driven over the console so this check does
    #    not itself depend on check 1 having passed.
    console = Console(gns3_host, nodes['NetworkAutomation-1']['console'])
    try:
        console.send('')
        console.expect(r'#\s*$', timeout=15, poke=True)
        out = console.run(f'ping -c2 -W3 {topo["switch"]["mgmt_ip"]}', quiet_seconds=6)
        if ' 0% packet loss' in out:
            ok(f'container reaches the switch at {topo["switch"]["mgmt_ip"]}')
        else:
            failures.append(f'container cannot ping the switch: {out.strip()[-160:]}')
        out = console.run(
            f'timeout 8 bash -c "echo > /dev/tcp/{topo["switch"]["mgmt_ip"]}/22" 2>/dev/null '
            '&& echo SSH_PORT_OPEN || echo SSH_PORT_CLOSED', quiet_seconds=10)
        if 'SSH_PORT_OPEN' in out:
            ok('switch SSH port open from the container')
        else:
            failures.append('switch SSH port not open from the container')
    finally:
        console.close()

    if failures:
        raise RebuildError('verification failed:\n  - ' + '\n  - '.join(failures))
    print('\nLab verified. PyCharm/SSH target: root@'
          f'{host_cfg["vmnet_ip"]} (key: {topo["automation_host"]["ssh_public_key"]})')


def main():
    parser = argparse.ArgumentParser(description='Rebuild or verify a GNS3 lab from a topology file')
    parser.add_argument('--verify', action='store_true',
                        help='only run the end-state checks; create and change nothing')
    parser.add_argument('--only', default=None,
                        help='comma-separated device names to configure (multi-vendor '
                             'topology only). Skips node/link creation and the end-to-end '
                             'pings - use it to retry one slow device.')
    parser.add_argument('--topology', default=None,
                        help='topology file to build (default: lab/topology.yaml, the '
                             'single-switch STIG lab). Use lab/topology_multivendor.yaml '
                             'for the R1/R2/SW1/SW2 lab in the "Network Automation" project.')
    args = parser.parse_args()

    topo = load_topology(args.topology)
    api = Gns3(topo['gns3']['server'])
    gns3_host = topo['gns3']['server'].split('//', 1)[-1].split(':')[0].split('/')[0]

    templates, public_key = preflight(api, topo)
    project_id = ensure_project(api, topo)

    # Two labs, one script. The multi-vendor topology carries a devices:
    # section and configures every device from it; the original single-switch
    # topology carries a switch: section and its own bespoke path. Branching on
    # the data rather than on a flag means neither lab can be built with the
    # other's logic by passing the wrong argument.
    multivendor = 'devices' in topo

    if args.verify:
        nodes = {n['name']: n for n in api.get(f'/projects/{project_id}/nodes')}
        missing = [name for name in topo['nodes'] if name not in nodes]
        if missing:
            raise RebuildError(f'nodes missing from the project: {", ".join(missing)}')
        if multivendor:
            failures = run_verify_pings(topo, nodes, gns3_host)
            if failures:
                raise RebuildError('verification failed:\n  - ' + '\n  - '.join(failures))
            print('\nLab verified.')
        else:
            verify(topo, nodes, gns3_host)
        return

    username, password = get_device_credentials()

    if args.only:
        if not multivendor:
            raise RebuildError('--only applies to the multi-vendor topology only')
        only = [n.strip() for n in args.only.split(',') if n.strip()]
        unknown = [n for n in only if n not in topo['devices']]
        if unknown:
            raise RebuildError(f'--only names devices not in the topology: {unknown}')
        nodes = {n['name']: n for n in api.get(f'/projects/{project_id}/nodes')}
        configure_devices(api, project_id, topo, nodes, gns3_host, username,
                          password, only=only)
        print(f'\nConfigured: {", ".join(only)}. End-to-end pings skipped '
              '(--only); run --verify for the full check.')
        return

    nodes = ensure_nodes(api, project_id, topo, templates)
    ensure_links(api, project_id, topo, nodes)

    if multivendor:
        start_nodes(api, project_id, nodes, list(topo['devices']))
        provision_container(api, project_id, topo, nodes, public_key, gns3_host)
        # Re-read: provisioning and the adapter changes above both mutate node
        # state, and the console ports are read from it.
        nodes = {n['name']: n for n in api.get(f'/projects/{project_id}/nodes')}
        configure_devices(api, project_id, topo, nodes, gns3_host, username, password)
        failures = run_verify_pings(topo, nodes, gns3_host)
        if failures:
            raise RebuildError('verification failed:\n  - ' + '\n  - '.join(failures))
        host_cfg = topo['automation_host']
        print(f'\nLab verified. Jump host: root@{host_cfg["vmnet_ip"]} '
              f'-> devices on {host_cfg["lab_ip"].rsplit(".", 1)[0]}.0/24')
    else:
        provision_container(api, project_id, topo, nodes, public_key, gns3_host)
        configure_switch(api, project_id, topo, nodes, gns3_host, username, password)
        verify(topo, nodes, gns3_host)


if __name__ == '__main__':
    try:
        main()
    except RebuildError as error:
        print(f'\nFAILED: {error}', file=sys.stderr)
        sys.exit(1)
