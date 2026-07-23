# Ansible replication of L2_stig_harden.py

An Ansible role/playbook that replicates the bulk L2S STIG hardening pass
`../L2_stig_harden.py` performs against S1/S2/S3, using `cisco.ios` instead
of Netmiko. Lives alongside the Python scripts on purpose - nothing here
touches `../netauto.py` or any of the `*_stig_harden.py`/`*_stig_audit.py`
scripts, and the two can be run independently.

## Status: not yet run against a live device

Everything here compiles/lints against known-good `cisco.ios.ios_config`
syntax, but hasn't been tested against S1/S2/S3 yet in this session - the
way every fix in the Python scripts got refined this session was by running
it live and reading the actual device response, and the same should happen
here before trusting this for anything real. Expect to find and fix a few
platform-specific surprises on the first real run, same as the Python side.

## What's covered

Everything in `L2_stig_harden.py`'s current (2026-07-23) state except the
two items below:

- All global (non-interface-specific) BASE_FIXES/UNNECESSARY_SERVICES_FIX/
  ARCHIVE_LOGGING_FIX/SSH_ENCRYPTION_FIX/VTY_SESSION_LIMIT_FIX/
  CONSOLE_EXEC_TIMEOUT_FIX
- VTP password, dual syslog servers, NTP (time sync + authentication),
  SNMPv3 auth/priv
- Native/default-access VLAN database creation (with the same VTP-
  transparent-mode prerequisite the Python script needs for the VLAN
  database to actually persist)
- DHCP snooping, scoped to genuinely-discovered user VLANs (mirrors
  `stig_common.discover_user_vlans()` - excludes `non_user_vlans` and the
  reserved 1002-1005 VLAN range)
- Interface-scoped access vs. trunk classification (same rule as
  `parse_switchports()`: trunk only if `switchport mode trunk` is present),
  with the matching per-bucket fixes: PortFast/UUFB/storm-control
  (speed-scaled, FastEthernet skipped)/802.1x-MAB for access ports;
  static-trunk/DHCP-snooping-trust/DAI-trust/allowed-VLAN-scoping/native-VLAN
  for trunk ports

## What's deliberately NOT covered yet

- **V-220629 (Root Guard)** - `L2_stig_harden.py` discovers this switch's
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

## Prerequisites

```
ansible-galaxy collection install -r requirements.yml
```

Fill in real values in `group_vars/l2_switches/vault.yml`, then encrypt it -
**never commit real secrets in plaintext**:

```
ansible-vault encrypt group_vars/l2_switches/vault.yml
```

## Running it

```
ansible-playbook playbooks/l2s_harden.yml --ask-vault-pass -e ansible_user=admin --ask-pass
```

(or supply credentials however your setup prefers - `--ask-pass` prompts for
the SSH password, matching this project's "never hardcode credentials"
convention on the Python side)
