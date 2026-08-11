# Ansible replication of the STIG hardening scripts

Ansible roles/playbooks that replicate the bulk STIG hardening passes the
Python scripts perform, using `cisco.ios` and `cisco.nxos` instead of
Netmiko:

| Role | Replicates | Target group |
|---|---|---|
| `l2s_stig_harden` | `../l2_stig_harden_global.py` + `_interfaces.py` | `l2_switches` |
| `l2s_stig_harden_ipsg` / `_dai` | `../l2_stig_harden_ipsg.py` / `_dai.py` | `l2_switches` |
| `nxos_stig_harden` | `../nxos_stig_harden_global.py` + `_interfaces.py` | `nxos_switches` |
| `stig_audit` | shells out to the `*_stig_audit.py` scripts | both |

Lives alongside the Python scripts on purpose - apart from `stig_audit`,
which deliberately shells out rather than reimplementing audit logic,
nothing here touches `../netauto.py` or any of the `*_stig_harden*.py`
scripts, and the two toolchains can be run independently (built for
interview/portfolio purposes, not because this project's small lab actually
needs a second toolchain - see the "Why this exists" section below).

## Status: confirmed working live

Run successfully end-to-end against **S1** and **S3** (2026-07-24) -
`failed=0` on both, with the expected `ignored` tasks matching known
`vios_l2` platform limitations (see "Confirmed-rejected commands" below).
**S2** wasn't fully tested (it lacked `aaa new-model` at the time, which is
no longer something this role even attempts - see V-220623 below), but
should now run clean there too since that dependency was removed from
scope entirely.

Every fix here (like every fix on the Python side this session) was found
by running it live against a real device and reading the actual response,
not assumed from documentation.

## Setup notes (things that weren't obvious the first time)

- **`group_vars` must live adjacent to the inventory file**
  (`inventory/group_vars/`), not just anywhere under `ansible/`. Ansible only
  auto-discovers `group_vars`/`host_vars` next to the inventory file or next
  to the playbook - anywhere else is silently ignored, which caused every
  vault/group-var-gated task to skip on the first live run with no error at
  all, just silent empty values.
- **`ansible-core` must be the pip install, not the distro package.** This
  project needs `ansible-core 2.13.13` (`pip3 install 'ansible-core==2.13.13'`,
  the newest a Python 3.8 host takes). Ubuntu also ships `ansible 2.9.6` as an
  apt package at `/usr/bin/ansible`, and if that ends up first on `PATH`,
  **every network module fails** with:

  ```
  ConnectionError: deprecated() got an unexpected keyword argument 'date'
  ```

  `Display.deprecated()` only gained its `date` parameter in ansible-base
  2.10, and `ansible.netcommon` 2.x+ calls it. The error surfaces from the
  persistent connection process, so it reads as a role or collection bug
  rather than a version mismatch - three `cisco.nxos` versions were pinned and
  unpinned chasing it before anyone ran `ansible --version`.

  **Check the interpreter before debugging anything else:**

  ```
  ansible --version    # want: ansible [core 2.13.13], /usr/local/bin/ansible
  ```

  Two quick tells that you are on the 2.9 package: `ansible-galaxy collection
  list` errors with `invalid choice: 'list'` (that subcommand arrived in 2.10),
  and the traceback paths read `/usr/lib/python3/dist-packages/ansible` rather
  than `/usr/local/lib/python3.8/dist-packages/ansible`.
- **`pip install ansible-core` can leave `packaging` uninstalled.** pip counts
  setuptools' *vendored* copy (`.../setuptools/_vendor/packaging`) as
  satisfying the dependency, but that path never lands on `sys.path`, so
  `ansible-galaxy` fails with:

  ```
  ERROR! Failed to import packaging, check that a supported version is installed
  ```

  `pip3 install packaging` reports "already satisfied" and changes nothing.
  Force it and verify by import, not by pip:

  ```
  pip3 install --ignore-installed packaging
  python3 -c "import packaging; print(packaging.__file__)"   # must NOT say setuptools/_vendor
  ```
- **`meta/runtime.yml` is necessary but not sufficient.** `cisco.nxos:4.4.0`
  declares `requires_ansible >=2.9.10`, which looks compatible with 2.9.6 and
  is not - the real constraint came from netcommon, one layer down. Check the
  declared requirement, then actually run the playbook against a device.
- **Pin `ansible.netcommon` explicitly**, even though the platform collections
  pull it in. Left implicit, it is free to drift to a version incompatible
  with the installed core, and it takes every platform down with it when it
  does. There is no version bind that works on 2.9.6: netcommon 2.x+ needs
  >=2.10, while netcommon 1.x lacks the `plugin_utils` that `cisco.ios:4.4.0`
  imports.
- **`ios_config` treats a rejected CLI command as fatal**, unlike Netmiko's
  `send_config_set()` (which just includes the error text in its output and
  keeps sending the rest of the batch). Every command already confirmed
  rejected on this lab's `vios_l2` is split into its own
  `ignore_errors: true` task, separate from
  commands that should actually succeed and fail loud if they don't -
  bundling a known-bad command into a bigger batch silently drops every
  command after it in that same task, not just the bad one.

## What's covered

Everything in `l2_stig_harden_global.py`'s current state except V-220629/V-220641a
(below) and V-220623's global prerequisites (moved out of scope entirely,
see below):

- All global (non-interface-specific) `BASE_FIXES`/`UNNECESSARY_SERVICES_FIX`/
  `ARCHIVE_LOGGING_FIX`/`SSH_ENCRYPTION_FIX`/`VTY_SESSION_LIMIT_FIX`/
  `CONSOLE_EXEC_TIMEOUT_FIX`
- VTP password, dual syslog servers, NTP (time sync + authentication),
  SNMPv3 auth/priv
- Native/default-access VLAN database creation - uses the `cisco.ios.ios_vlans`
  **resource module** (state-based: `config: [{vlan_id, name}, ...]` +
  `state: merged`) instead of raw `ios_config` lines, as a demonstration of
  that style. Everything else in this role still uses raw `ios_config` -
  most of the bulk pass has no matching resource module at all (narrow,
  STIG-specific commands aren't general-purpose config domains Cisco built
  structured support for)
- DHCP snooping, scoped to genuinely-discovered user VLANs (mirrors
  `stig_common.discover_user_vlans()` - excludes `non_user_vlans` and the
  reserved 1002-1005 VLAN range)
- Interface-scoped access vs. trunk classification (same rule as
  `parse_switchports()`: trunk only if `switchport mode trunk` is present),
  with the matching per-bucket fixes: PortFast/UUFB/storm-control
  (speed-scaled, FastEthernet skipped)/802.1x-MAB (per-port only, see below)
  for access ports; static-trunk/DHCP-snooping-trust/DAI-trust/allowed-
  VLAN-scoping/native-VLAN for trunk ports

### Confirmed-rejected commands (ignore_errors, kept for real hardware)

Same platform limitations catalogued in the main README's Notes section:
`mls qos`, `file privilege 15`, three of the
unnecessary-services lines (`no ip dns server`/`no ip identd`/`no service
call-home`), UUFB (`switchport block unicast`), the per-port 802.1x/MAB
commands, and storm control. All rejected outright on this lab's `vios_l2`,
correct commands for real hardware.

## What's deliberately NOT covered

- **V-220629 (Root Guard)** - `l2_stig_harden_global.py` discovers this switch's
  live STP root port(s) first (`stig_common.discover_root_port_interfaces`)
  and excludes them, because pushing Root Guard to your own root port forces
  it into root-inconsistent/blocking state - a real outage, not a
  theoretical risk. Doing that safely in Ansible needs either a custom
  filter/module to parse `show spanning-tree` structurally, or accepting a
  less precise heuristic. Left out rather than guessing.
- **V-220641a (disabled ports -> unused VLAN)** - needs per-port shutdown-
  state detection this role doesn't gather. Straightforward to add later
  (same running-config text is already being fetched in `interfaces.yml`),
  just not done yet.
- **V-220623a/b (dot1x system-auth-control + AAA method list)** - these two
  global commands need `aaa new-model` already active to be valid syntax at
  all (confirmed live: rejected on S2, which doesn't have it, succeeded on
  S1/S3, which do from prior `l2_stig_harden_aaa.py` runs). On the Python
  side these were moved into `l2_stig_harden_aaa.py`, right after
  `aaa new-model`, so they're never attempted until the prerequisite is
  confirmed active. There's no Ansible equivalent of `l2_stig_harden_aaa.py`
  yet (AAA/RADIUS push, with its own enable-secret verification step) to
  receive them, so they're simply not pushed here at all - only the
  per-port V-220623 commands (`authentication port-control auto`/
  `dot1x pae authenticator`/`mab`) remain in this role, matching
  `l2_stig_harden_global.py`'s current scope exactly.

## Why this exists

This project's Python/Netmiko toolchain already works well at this scale
(7-8 devices, one person maintaining it) - this role isn't "better," it's
a second, independently-working implementation of the same STIG logic,
built to demonstrate Ansible experience. The real reasons organizations
prefer Ansible are mostly about team/hiring standardization, inventory
management at much larger scale, and vendor-maintained low-level plumbing
- not because it's technically superior to a well-tested custom toolchain
for a setup this size. See project chat/memory for the fuller discussion.

## Prerequisites

On a fresh host (Ubuntu 20.04, Python 3.8, confirmed working sequence):

```bash
apt install -y python3-venv python3-pip sshpass
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install -r ../requirements.txt   # Netmiko/PyYAML, same venv as the Python scripts
pip install ansible
ansible-galaxy collection install -r requirements.yml
```

Fill in real values in `inventory/group_vars/l2_switches/vault.yml`, then
encrypt it - **never commit real secrets in plaintext**:

```
ansible-vault encrypt inventory/group_vars/l2_switches/vault.yml
```

## Running it

```
ansible-playbook playbooks/l2s_harden.yml --ask-vault-pass -e ansible_user=admin --ask-pass
```

(or supply credentials however your setup prefers - `--ask-pass` prompts for
the SSH password, matching this project's "never hardcode credentials"
convention on the Python side). Add `--limit S1` (or `S2`/`S3`) to target
just one device.
