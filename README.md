# Network Automation — DISA STIG Compliance for Cisco Infrastructure

Python and Ansible tooling that **audits and remediates Cisco network devices against DISA STIG benchmarks** — the hardening standard required on U.S. Department of Defense networks. Built on [Netmiko](https://github.com/ktbyers/netmiko) over SSH.

Manually STIG-checking a single switch means checking ~65 rules by hand against the running-config, then doing it again after every change. The scripts I created automate the compliance check across three platforms, and pushes the fixes.

| Platform | DISA Benchmarks | Rules | Automated checks |
|---|---|---|---|
| Cisco IOS Switch | L2S + NDM | 65 | 61 |
| Cisco NX-OS Switch | L2S + NDM | 64 | 57 |
| Cisco IOS Router | NDM + RTR | 127 | 59 |

Rules needing external infrastructure (PKI, org-defined DoS safeguards) or topology/policy judgment are reported **NOT AUTOMATED** rather than guessed at — a false pass on a compliance tool is worse than no answer. Every rule check is coded against the STIG's literal Check Text, and every fix against its Fix Text.

Validated against a 7-device virtual lab (2 IOS routers, 3 IOSvL2 switches, 2 NX-OS cores). Ansible roles under [`ansible/`](ansible/) replicate the Python hardening for fleet-wide runs. See [`docs/DESIGN.md`](docs/DESIGN.md) for the reasoning behind script isolation, run order, and credential handling.

## What's here

Everything runs from the repository root — `python3 scripts/<name>.py`. Names below are bare for
readability. `inventory.yaml`, `secrets.yaml`, `checklists/`, `backups/` and `audit_logs/` sit at
the root, beside `scripts/` rather than inside it.

Anything marked **configures devices** writes to running-config. Everything else only reads.
The reasoning behind the ones that look odd — why scripts are split, what is deliberately
not pushed, which STIG readings were argued over — is in [`docs/DESIGN.md`](docs/DESIGN.md).

### Shared
| | |
|---|---|
| `netauto.py` | Inventory loading, credential prompting, Netmiko SSH, privilege escalation. |
| `stig_common.py` | The audit engine: reads a `.cklb`, checks the device, reports PASS/FAIL/NOT APPLICABLE/NOT AUTOMATED. Each answered rule also names what it was read from and the filtered command that shows the same evidence on the switch. |
| `inventory.yaml` | Devices and hardening config — NTP/syslog/RADIUS addresses, VLAN IDs, management subnet. No credentials. Written as JSON, which PyYAML parses unchanged. |
| `secrets.yaml` *(gitignored)* | Secrets for the `*_harden*.py` scripts. Copy `secrets.yaml.example`. |

### Read-only and diagnostics
| | |
|---|---|
| `show_command.py` | Run a show command against one or more devices. |
| `health_check.py` | Reachability, unexpected interface state, error counters, CPU, temperature/power/fans. |
| `arp_inventory.py` | What is live on a subinterface, from the router's ARP table, as a CSV. |
| `pdf_ips.py` | Addresses out of a PDF network diagram, with the page and label beside each. |
| `merge_walk_csvs.py` | Merges the per-run CSVs the SecureCRT walks write into one file, newest row per switch. |
| `backup_config.py` | Back up running-config + VLANs; a latest copy per device plus a pruned archive. |
| `config_diff.py` | Compare current running-config/VLANs against the last backup. |

### Configuration
| | |
|---|---|
| `config_loopback.py` | **Configures devices.** Create or update a loopback interface. |
| `push_config.py` | **Configures devices.** Push config commands from a file to one or more devices. |
| `save_config.py` | running-config to startup-config. Run it *after* a harden pass **and** its audit. |
| `l2_quiet_console.py` | Disable live console/monitor logging. Quality-of-life, not a STIG item — messages still buffer and forward to syslog. |
| `l2_device_tracking.py` | SISF `device-tracking policy` for host IP visibility. Not a STIG requirement, IOS XE only. |
| `lab/rebuild_lab.py` | Rebuilds the GNS3 lab from `lab/topology.yaml`. |

### Auditing
| | |
|---|---|
| `l2_stig_audit.py` | IOS XE Switch L2S/NDM (default) or IOS Switch (`--checklist ios`). Interface-scoped, with live discovery for root ports, VTP and user VLANs. `--from-capture` audits collected output, `--to-cklb` writes a STIG Viewer 3 checklist. |
| `nxos_stig_audit.py` | NX-OS Switch L2S/NDM. |
| `ios_router_audit.py` | IOS Router NDM/RTR. Most RTR rules need topology context and report NOT AUTOMATED. |
| `capture.py` | Offline auditing from a capture file. Refuses a malformed, truncated or partial capture rather than auditing it. |
| `sanitize_capture.py` | Redact a capture so it can leave the network. Refuses to write if anything sensitive survives the pass. |
| `ios_xe_rule_map.py` | Maps 60 of the IOS XE STIG's 64 rules onto the IOS rule that asks the same thing, accepting a pair only where the finding sentence matches in both. |

### SecureCRT
Run inside SecureCRT (Script → Run) on a host where netmiko cannot be installed. Copy the folder
together — they import from each other. Host keys are **not** accepted blind, so a switch whose key
SecureCRT has never seen stops an unattended run on a modal dialog; connect to it once by hand first.

| | |
|---|---|
| `capture_l2s.py` | One open session: send the read-only commands, audit them, write the `.cklb`. Cannot connect to anything, so it cannot be aimed at the wrong device. |
| `capture_l2s_bulk.py` | The same across every saved session, unattended. One `run_log_<stamp>.csv` accounting for every session, including the ones nothing answered from. |
| `inventory_l2s.py` | `show version` per session into one `inventory_<stamp>.csv`. A stack is one row per chassis. |
| `harden_l2s_bulk.py` | **Configures devices.** Logging/audit, access control, SSH crypto, the V-220534 service block. vty limit opt-in. Never writes startup-config. |
| `harden_access_ports_bulk.py` | **Configures devices.** The access-port fixes on every host-facing port. Never sends a trunk command. Reads and expands interface templates before classifying any port. |

### Hardening — IOS / IOS XE switch
Run in the order listed. Each is separate because of what it can cost you if it is wrong.

| | |
|---|---|
| `l2_stig_harden_global.py` | **Run first.** BPDU/Loop Guard, Rapid-PVST, UDLD, IGMP + DHCP snooping, archive logging, VTP, NTP, syslog, SNMPv3. |
| `l2_stig_harden_logging_access.py` | Logging/audit, access control, SSH crypto, unnecessary services. Touches no forwarding, so it needs no change window. vty lines behind `--with-vty`. |
| `l2_stig_harden_access_ports.py` | Host-facing ports: access mode, PortFast, UUFB, storm control, unused VLAN on shut ports. Safe on a working day. 802.1x is deliberately not pushed. |
| `l2_stig_harden_trunk_ports.py` | Uplink ports: `nonegotiate`, snooping/DAI trust, allowed-VLAN list, native VLAN, Root Guard. **Its own change window** — these decide what the uplink carries. |
| `l2_stig_harden_ipsg.py` | IP Source Guard (V-220634). Static-host caveat in Notes. |
| `l2_stig_harden_dai.py` | Dynamic ARP Inspection (V-220635). Same caveat. |
| `l2_stig_harden_acl.py` | vty management ACL (V-220575). Its own script — a wrong `access-class` locks out every future session. |
| `l2_stig_harden_aaa.py` | **Run last.** `aaa new-model`, RADIUS auth, password policy. |

### Hardening — NX-OS
| | |
|---|---|
| `nxos_stig_harden_global.py` | Enables the required features first, then applies the global fixes. |
| `nxos_stig_harden_interfaces.py` | Per-port: UUFB, IPSG, storm control, DAI trust, VLAN pruning. |
| `nxos_stig_harden_acl.py` | Management ACL (V-220479). |
| `nxos_stig_harden_aaa.py` | RADIUS auth and accounting. |

### Hardening — IOS router
| | |
|---|---|
| `ios_router_stig_harden_global.py` | Disable gratuitous ARP, CDP, AUX; enable CEF; NTP, syslog, SSH FIPS ciphers. |
| `ios_router_stig_harden_acl.py` | vty management ACL (V-215667). |
| `ios_router_stig_harden_aaa.py` | AAA/RADIUS plus password complexity. `local` stays last, so SSH still works if RADIUS is unreachable. |
| `ios_router_stig_harden_urpf.py` | uRPF (V-216989) on external interfaces. Needs `allow-default` — see Notes. |

## Requirements

```
pip install -r requirements.txt
```

netmiko and PyYAML are real dependencies here. Netmiko is still imported inside
`netauto.connect()` rather than at module scope, so `--from-capture` audits and the SecureCRT
collectors never load it.

Copy `secrets.yaml.example` to `secrets.yaml` and fill in real values before running any
`*_stig_harden*.py` script that needs them.

## Usage

```bash
# Run a show command against one or more devices
python3 scripts/show_command.py "show ip interface brief" R1
python3 scripts/show_command.py "show ip interface brief" R1 R2 S1

# Operational health of all devices, or specific ones
python3 scripts/health_check.py
python3 scripts/health_check.py R1 S1

# Configure a loopback, or push commands from a file
python3 scripts/config_loopback.py R1 1.1.1.1 255.255.255.255 --interface 0
python3 scripts/push_config.py commands.txt R1 R2

# Back up, then diff against the last backup
python3 scripts/backup_config.py --all
python3 scripts/config_diff.py S1

# STIG audit. Defaults to the IOS XE STIG; --checklist ios for classic IOS.
# The two share no rule IDs, so the wrong one reports every rule NOT AUTOMATED.
python3 scripts/l2_stig_audit.py S1 --checklist ios
python3 scripts/nxos_stig_audit.py NXCore1
python3 scripts/ios_router_audit.py R1

# Audit without connecting: collect the show commands into a file - a logged
# terminal session works - then audit it anywhere. --capture-to records a live
# run, and auditing that file must give the same report.
python3 scripts/l2_stig_audit.py S1 --capture-to captures/S1.capture --checklist ios
python3 scripts/l2_stig_audit.py S1 --from-capture captures/S1.capture --checklist ios

# Write the verdicts into a STIG Viewer 3 checklist instead of retyping 64
# rules. NOT AUTOMATED becomes not_reviewed, never not_a_finding.
python3 scripts/l2_stig_audit.py SW01 --from-capture captures/SW01.capture --to-cklb checklists/out/

# Redact a capture so it can leave the network. Refuses to write at all if
# anything it recognises as sensitive survives the pass.
python3 scripts/sanitize_capture.py captures/SW01.capture

# STIG hardening for an L2 switch - run in this order:
python3 scripts/l2_stig_harden_global.py S1
python3 scripts/l2_stig_harden_logging_access.py S1
python3 scripts/l2_stig_harden_access_ports.py S1
python3 scripts/l2_stig_harden_trunk_ports.py S1     # its own change window
python3 scripts/l2_stig_harden_ipsg.py S1
python3 scripts/l2_stig_harden_dai.py S1
python3 scripts/l2_stig_harden_acl.py S1
python3 scripts/l2_stig_harden_aaa.py S1             # last

# NX-OS hardening - global first, then the isolated scripts
python3 scripts/nxos_stig_harden_global.py NXCore1
python3 scripts/nxos_stig_harden_interfaces.py NXCore1
python3 scripts/nxos_stig_harden_acl.py NXCore1
python3 scripts/nxos_stig_harden_aaa.py NXCore1

# IOS router hardening - same order
python3 scripts/ios_router_stig_harden_global.py R1
python3 scripts/ios_router_stig_harden_urpf.py R1
python3 scripts/ios_router_stig_harden_acl.py R1
python3 scripts/ios_router_stig_harden_aaa.py R1

# Persist the result - only after re-auditing and confirming it is what you wanted.
python3 scripts/save_config.py --all

# Optional, non-STIG
python3 scripts/l2_quiet_console.py S1
python3 scripts/l2_device_tracking.py S1

# Tests - no framework, no device needed
for t in tests/test_*.py; do python3 "$t"; done
```

## Getting a report into STIG Viewer 3

`--to-cklb` is a flag on the audit, not a separate conversion step: one run produces
both the printed report and the checklist file. The end-to-end walkthrough on Windows —
collect, audit, open, and what a re-run does to anything typed into STIG Viewer — is in
[`docs/STIG-VIEWER.md`](docs/STIG-VIEWER.md).

## Notes

- Devices are defined in `inventory.yaml` by name, host, and Netmiko `device_type` (e.g. `cisco_ios`, `cisco_nxos`).
- Backups go to `backups/`, dated copies to `backups/archive/`. Scripts that push config append a JSON-line record to `audit_logs/audit.log`. Neither is tracked in git.
- The L2 audit prints, above the report, which VLANs it classified as user VLANs and why — a VLAN wrongly excluded there produces a quiet false PASS.
- Rules needing external infrastructure or topology judgment are reported NOT AUTOMATED rather than guessed at.
- `l2_stig_harden_ipsg.py` and `l2_stig_harden_dai.py` both trust only the DHCP snooping binding table, so a statically-addressed host with no lease has its traffic dropped.
- `ios_router_stig_harden_urpf.py` is pushed with `allow-default`; strict mode drops sources reachable only via the default route, which on this lab includes the management path.
- Several STIG-required commands do not exist or function on the lab's `vios_l2` image — see [`docs/DESIGN.md`](docs/DESIGN.md).

## Roadmap

- [x] Environment checks in `health_check.py` (temperature, power supply, fans)
- [x] Audit logging to file
- [x] Interface-scoped L2S STIG hardening (IPSG, DAI, storm control, UUFB, VLAN classification, 802.1x/MAB)
- [x] NTP audit and hardening, redundant authenticated time sources
- [x] AAA/RADIUS (V-220587/617) and password complexity policy (V-220589-594)
- [x] vty management ACL (V-220575)
- [x] SNMPv3 auth/priv (V-220604/605) — config-only, no NMS in this lab to poll it
- [ ] Config push dry-run / diff-before-push mode
- [ ] Config removal/undo mode
- [ ] Static-host binding gap for IPSG/DAI — needs a dynamic fix diffing `show ip device tracking all` against `show ip dhcp snooping binding`
- [ ] Interface-scoped RTR STIG hardening (directed broadcast, ICMP redirects/unreachables/mask-reply, proxy ARP, LLDP transmit)
- [ ] Port interface-scoped hardening to `nxos_stig_audit.py`/`nxos_stig_harden_global.py`
- [ ] Validate `l2_device_tracking.py` and the AAA/ACL/password-policy scripts against real IOS-XE hardware
- [ ] Nornir-based parallel execution for larger inventories
- [ ] Ansible playbook equivalents for core workflows
