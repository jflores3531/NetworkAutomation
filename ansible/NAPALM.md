# The multi-vendor Ansible layer (NAPALM + per-platform collections)

Ansible content for the **multi-vendor lab**: Cisco switches and routers,
Juniper switches, and a Palo Alto firewall. NAPALM is the abstraction for
everything NAPALM can drive; where it cannot, the platform's own certified
collection is used rather than worked around.

This lives beside the STIG roles in the same directory, shares their inventory
file, and **changes none of them**. The STIG groups (`l2_switches`,
`nxos_switches`) gained NAPALM coverage by becoming children of the driver
groups below, which added variables to them and altered nothing they already
had. See [`README.md`](README.md) for that toolchain.

## Status: Juniper confirmed live, everything else offline only

This repository's convention is to name the device and the date (see the
"confirmed working live" sections in [`README.md`](README.md)), so:

### Confirmed live — JSW1, 2026-09-13

vJunos 26.2R1.7, from the lab's Python 3.12 controller (ansible-core 2.21.4,
`napalm.napalm` 0.9.13, `junipernetworks.junos` 11.1.1):

- **`junos_baseline` applied**, `changed=6`, and an immediate `--check -D`
  re-run reported `changed=0` across all 15 tasks. Both `junos_hostname` and
  `junos_ntp_global` committed, so those schemas are settled.
- **`napalm_facts` collected all ten junos getters**, `unsupported_getters: []`.
- **`napalm_validate` reported COMPLIES**, returning `compliance_report` as a
  top-level key.

Three things had to be fixed before any of that could start, and the first is
the one worth remembering: **there is no `napalm.ansible` collection on
Galaxy.** NAPALM's is `napalm.napalm`. Every role called the wrong name, and
the offline stubs registered the same wrong name — so the suite passed while no
real run could ever have begun. The full list is in "Verify on first contact"
below, and the lesson is in what a stub cannot tell you: it will happily
implement a collection that does not exist.

### Not yet run against hardware

Everything Cisco (`cisco_baseline`, and the `router_on_a_stick` template with
its HSRP), everything Palo Alto (`panos_baseline`, the config export in the
backup play), and `napalm_backup`, `napalm_healthcheck`, `napalm_push`,
`junos_safe_push` and `preflight` on any real device. JSW2 is bootstrapped and
answers NETCONF, but the roles have only been run against JSW1.

### What offline validation covers

Every playbook and role executed end to end against stub modules returning
realistic device data, with these results:

- all 14 playbooks pass `--syntax-check`
- `ansible/tests/run_offline.py` drives all of it as 22 scenarios and asserts on
  what each run printed and wrote, not just its exit code — every one of the
  bugs below exited 0 while being wrong. The suite is mutation-tested: breaking
  the fix again fails it
- `preflight` reports per-device readiness across the whole inventory without
  aborting, and distinguishes unreachable / port-open-login-failed /
  NETCONF-not-enabled —
  each branch verified by pointing it at a local listener
- `napalm_facts` collects 9 getters, merges them, and writes per-device JSON
- an unsupported getter is tolerated, named in the run output, and costs only
  itself — verified by making the stub refuse two of them
- `napalm_healthcheck` correctly identified an enabled-but-down port, a port
  over the error threshold, the *highest* CPU core rather than an average
  (91% of two cores), RAM at 75%, a temperature alert, and a failed PSU
- `napalm_backup` wrote latest + archive copies and detected running ≠ startup
- `napalm_validate` produced a compliance report and **failed the play** on
  non-compliance — verified by making the stub report non-compliant
- `napalm_config_push` and `junos_safe_push` render correct per-platform config
  and stop at the diff unless explicitly told to commit
- `cisco_baseline`, `junos_baseline` and `panos_baseline` assemble every module
  argument correctly from inventory, and their opt-in gates (firewall policy,
  PAN-OS commit) stay shut unless set

Running it rather than reading it is what found the bug worth recording, which
was a **silent false pass** — the worst kind for a readiness check:

**Every device reported `READY` while all twelve were unreachable.**
`is succeeded` is true for a *skipped* task, because a skipped result carries no
`failed` key. Every check in the role is skipped when the port check fails, so
"nothing ran" read identically to "everything passed". Each test now also
asserts that the task actually ran.

It would have survived any amount of review of the YAML; only twelve
placeholder addresses and a `0/12 ready` expectation caught it. A second bug,
in the plays rather than a role, is written up under "Why these plays set both
`connection: local` and `ansible_connection`" below.

**A correction, since this file is the record.** That failure was first written
up here as two bugs, the second being Jinja truthiness — a boolean built in a
`vars:` block rendering as the string `"False"`, which is truthy. Mutation
testing says otherwise: removing the `.skipped` guards fails the suite, while
removing `| bool` does not, and on ansible-core 2.19 a vars-block boolean comes
back as a real `bool`. So truthiness was never the cause here. The `| bool`
guards stay, for a narrower reason than originally claimed: this project runs a
mix of ansible-core versions, and on older ones that coercion is real.

### What a review pass then found

A separate review of the whole branch turned up fourteen issues, all fixed here.
The ones worth knowing about, because each would have cost a lab session:

- **Validation asserted `vendor: Cisco` against the Juniper switches.** The
  expectation was a role-wide default, so both would have failed validation -
  and failed the last step of `multivendor_site.yml` - for being Juniper. Vendor is now set per driver group, and unset means "do not check"
  rather than "assume Cisco". The suite gained a regression test that reads the
  rendered intent, which is what the old validate stub could not do.
- **A health check with no counters available reported "0 over the threshold".**
  Silence read as good news. Both optional getters now carry an availability
  flag through the report, the saved JSON and the gate.
- **RAM was under-reported.** NAPALM's `available_ram` is *total installed* RAM,
  not free RAM, so dividing by `available + used` treated total as free: 3 GiB
  used of 4 GiB read as 43% instead of 75%.
- **The `--fail` gate ignored CPU, temperature and PSU findings**, and
  `napalm_cpu_threshold`/`napalm_memory_threshold` were referenced nowhere. A
  device with a dead power supply and a pegged control plane passed the check
  whose entire purpose is "do not start pushing config to a device that is
  already unhappy".
- **`napalm_config_push` would push an empty candidate**, which with
  `replace_config: true` is a request to erase a device's configuration - and
  the shipped placeholders are exactly the state that renders empty.
- **A gather where every getter failed exited 0** and overwrote a good facts
  file with `"data": {}`.
- **Committed examples did not match what the roles consume**: `ipv4_address` +
  `ipv4_netmask` where the role needs `ipv4_cidr`, and a Junos RVI written
  `name: irb.10` with no `unit`, which silently configures `irb` unit 0 - a real
  interface, the wrong one, no error.
- **A Nexus added to `nxos_lab`, as `hosts.yml` tells you to,** inherited no
  connection variables and died on an undefined one. The vars moved to the
  parent group.
- **`preflight_login=false` made every reachable device report NOT READY**, so
  the flag was unusable in the one case it exists for.

What that does **not** prove: that a single module argument is spelled the way
the installed collection expects, or that any device accepts what is sent. The
lab is the next step, and the "Verify on first contact" list at the bottom is
what to check while doing it.

## The device set and what drives each

| Platform | Reads / diffs | Config | Transport |
|---|---|---|---|
| Cisco IOS / IOS-XE (switches, routers) | NAPALM `ios` | `cisco.ios` resource modules | SSH (Netmiko) / `network_cli` |
| Cisco NX-OS | NAPALM `nxos_ssh` | `cisco.nxos` resource modules | SSH / `network_cli` |
| Juniper (EX/QFX) | NAPALM `junos` | `junipernetworks.junos` resource modules | NETCONF both ways |
| Palo Alto | `panos_facts` + config export (NAPALM optional, see below) | `paloaltonetworks.panos` | XML API |
| Fortinet — **parked** | — | `fortinet.fortios` / `fortinet.fortiswitch` | REST API |

### Why not NAPALM for everything

NAPALM has no driver for FortiOS, and only a community-maintained one for
PAN-OS (`napalm-panos`, whose getters stop at facts, config and interfaces).
Neither models what a firewall *is* — zones, address objects, security rules,
NAT — so a firewall configured through NAPALM would be configured by pushing
text at it, giving up every advantage NAPALM is used for here.

The inventory says this out loud rather than hiding it: `napalm_devices` is the
group of platforms whose drivers ship **with NAPALM itself** (`ios`,
`nxos_ssh`, `junos`), and it is what the read-only plays target. `napalm_panos`
exists as a separate, empty group — putting `PA1` in it is a claim that
`pip install napalm-panos` has been done and proven, and nothing depends on it.

### Why not resource modules for everything

Because reading a fleet shouldn't need one code path per vendor.
`napalm_healthcheck` answers the same questions
[`../scripts/health_check.py`](../scripts/health_check.py) does — interfaces
that should be up and aren't, error counters, CPU, RAM, temperature, PSUs and
fans — in **one** set of tasks for every platform, because the `environment`
and `interfaces` getters return the same structure everywhere. The Python
version carries a per-platform command table and parsers, several of which
exist because they were first wrong against real hardware.

## The division of labour

    NAPALM          multi-vendor reads (facts, backups, health, validation)
                    and device-computed diffs before a push

    resource        per-feature configuration that must be idempotent, because
    modules         they compare PARSED DEVICE STATE rather than config text

That split is the design, and it is drawn where it is for a specific reason.
`ios_config` and Netmiko both decide what to send by comparing strings on the
controller, which is why so much of [`README.md`](README.md) is a catalogue of
lines that never matched: `deny   ip any any log-input` column-aligned with
three spaces, `storm-control broadcast level 40.00`, `spanning-tree portfast
edge`, and every NX-OS default-valued line that `show running-config` omits
entirely (`radius-server retransmit 1`; V-220690 matching **zero** of 59
disabled ports).

A NAPALM diff is computed **by the device** against a candidate configuration,
so it says what would actually change. A resource module compares structured
state, so it reports `changed` honestly. Neither can be fooled by whitespace.

What NAPALM's config path cannot do is manage a VLAN — its unit is a
configuration file. So it gets the reads and the diffs, and the resource
modules get the writes.

## The lab this describes

Seven nodes: six network devices plus the automation host. Firewall at the
perimeter, a redundant router pair below it as the internal gateway, switches
pure layer 2.

```
                        VMnet8 / outside
                              │ ethernet1/1 → zone untrust
                    ┌────────────────────┐
                    │   PA1   PAN-OS     │   edge
                    └────────────────────┘
                              │ ethernet1/2 → zone trust  10.0.1.1/29
                        [ TransitSw ]   unmanaged, 0 RAM
                          │          │
                 ┌────────────┐  ┌────────────┐
                 │  R1  IOSv  │  │  R2  IOSv  │  Gi0/1  .2      .3
                 │  HSRP actv │  │  HSRP stby │  transit VIP .4
                 └────────────┘  └────────────┘
                    │ Gi0/2          │ Gi0/2     trunks (10,20 · native 999)
                 ┌────────────┐  ┌────────────┐
                 │  SW1 IOSvL2│══│  SW2 IOSvL2│  pure L2
                 └────────────┘  └────────────┘
                   │      └────────┐   │     │
                   │   ┌───────────┼───┘     │
              ┌──────────┐     ┌──────────┐  │
              │   JSW1   │─────│   JSW2   │──┘  dual-homed, STP blocks one
              │  USERS   │     │ SERVERS  │
              └──────────┘     └──────────┘
```

| | Address |
|---|---|
| Management | 10.10.50.0/24 — automation .10, R1 .11, SW1 .12, SW2 .13, JSW1 .14, JSW2 .15, PA1 .16, R2 .17 |
| Transit (PA1 ↔ routers) | 10.0.1.0/29 — PA1 .1, R1 .2, R2 .3, **HSRP VIP .4** |
| VLAN 10 USERS | 10.0.10.0/24 — R1 .2, R2 .3, **HSRP VIP .1** |
| VLAN 20 SERVERS | 10.0.20.0/24 — R1 .2, R2 .3, **HSRP VIP .1** |
| VLAN 99 MGMT | the management segment; SW1/SW2 reach it via an access port + SVI |
| VLAN 999 | native on every trunk, and the unused-port VLAN |
| Outside | PA1 `ethernet1/1` 192.168.231.60/24 via .2 (VMware NAT, per `../lab/topology.yaml`) |

Inventory carries these addresses for real rather than as `x.x.x.x`, unlike the
STIG groups — they describe one GNS3 lab on one workstation, and
`../lab/topology.yaml` already commits the same management segment. A real
site's addressing still belongs only in gitignored files.

Why the topology is shaped this way, in automation terms: **every Cisco device
exercises a different half of `cisco_baseline`.** The routers carry every L3
interface, static route and the OSPF process; the switches carry VLANs, trunks
and one management SVI and no routing at all. That is what the
`ios_routers`/`ios_switches` split was built for. The Cisco↔Juniper trunks are
where native-VLAN and allowed-VLAN modelling differs between platforms, and
LLDP across that seam is what `napalm_facts` reads the topology back from.

Two things sit outside the resource modules, both on the routers:
`encapsulation dot1Q` (no module in `cisco.ios` covers it, and
`ios_l3_interfaces` will address a subinterface without it — an interface with
an IP that forwards nothing) and HSRP (a module exists in recent `cisco.ios`,
but the schema needs confirming against the installed version first). Both go
through `napalm_config_push` with `templates/router_on_a_stick.j2`, which gets
the device-computed diff and depends on no unverified module:

```bash
ansible-playbook playbooks/napalm_push.yml --limit R1 \
    -e napalm_config_template=router_on_a_stick.j2      # diff only
ansible-playbook playbooks/napalm_push.yml --limit R1 \
    -e napalm_config_template=router_on_a_stick.j2 -e napalm_commit=true
```

One router at a time. Pushing HSRP to both at once, with a mistake in it, takes
out the gateway for every VLAN simultaneously.

## Layout

    inventory/hosts.yml               all groups, STIG and multi-vendor
    inventory/group_vars/
      all/vars.yml                    napalm_provider, output dirs
      napalm_ios|napalm_nxos|
        napalm_junos/vars.yml         driver + getter list per platform
      ios_switches|ios_routers|
        juniper_switches/vars.yml     intended config per platform
      palo_alto/vars.yml              provider, vsys, intended config
      palo_alto/vault.yml.example     API key template

    roles/preflight                   reachability + prerequisites, per device
    roles/napalm_facts                multi-vendor fact collection -> JSON
    roles/napalm_healthcheck          interfaces, counters, environment
    roles/napalm_backup               config backup, latest + archive, diffed
    roles/napalm_validate             compliance report against declared state
    roles/napalm_config_push          diff-before-push, any NAPALM platform
    roles/cisco_baseline              cisco.ios / cisco.nxos resource modules
    roles/junos_baseline              junipernetworks.junos resource modules
    roles/junos_safe_push             confirmed-commit push (see Safety)
    roles/panos_baseline              paloaltonetworks.panos, candidate + commit
    roles/fortigate_baseline          parked
    roles/fortiswitch_baseline        parked

Groups are organised **by driver**, not by role-in-the-network, so that one
`group_vars` file sets `napalm_dev_os` for every device that shares a driver:

    napalm_devices
    ├── napalm_ios      → l2_switches (STIG), ios_switches, ios_routers
    ├── napalm_nxos     → nxos_switches (STIG), nxos_lab
    └── napalm_junos    → juniper_switches
    palo_alto           (connection: local, XML API)
    napalm_panos        (empty; community driver, opt-in)
    fortinet            (parked)

## Playbooks

Start here, every session. One line per device: reachable, credentials good,
and what answered — and it never stops at the first failure, because the point
is a survey of all ten devices rather than the first bad one:

```bash
ansible-playbook playbooks/preflight.yml --ask-vault-pass
ansible-playbook playbooks/preflight.yml -e preflight_fail_on_not_ready=true   # as a gate
```

It exists because every failure it catches surfaces later disguised as
something else: a Juniper switch missing `set system services netconf ssh`
looks like bad credentials while CLI SSH keeps working (so it checks 830, then
22, and says which answered); a missing NAPALM driver fails on the controller,
making all ten devices look broken at once; a wrong Palo Alto API key passes
every read and fails at the first write.

Read-only, safe against everything, `napalm_devices` fleet-wide:

```bash
ansible-playbook playbooks/napalm_facts.yml
ansible-playbook playbooks/napalm_healthcheck.yml
ansible-playbook playbooks/napalm_backup.yml -D      # -D prints the config diff
ansible-playbook playbooks/napalm_validate.yml
```

Configuration, each targeting only its own platform's groups:

```bash
ansible-playbook playbooks/cisco_baseline.yml --ask-pass -e ansible_user=admin --check -D
ansible-playbook playbooks/junos_baseline.yml  --ask-pass -e ansible_user=admin --check -D
ansible-playbook playbooks/panos_baseline.yml  --ask-vault-pass
```

Pushes, dry run first, then commit:

```bash
# any NAPALM platform - loads a candidate, prints the device's diff, discards it
ansible-playbook playbooks/napalm_push.yml -e napalm_config_template=example_ios.j2 --limit SW1
ansible-playbook playbooks/napalm_push.yml -e napalm_config_template=example_ios.j2 \
    -e napalm_commit=true --limit SW1

# Juniper, behind a commit the switch will revert on its own
ansible-playbook playbooks/junos_safe_push.yml -e junos_config_template=example_junos.j2 --limit JSW1
ansible-playbook playbooks/junos_safe_push.yml -e junos_config_template=example_junos.j2 \
    -e junos_commit=true --limit JSW1
```

Everything in order, once each piece has been run on its own:

```bash
ansible-playbook playbooks/multivendor_site.yml --ask-vault-pass \
    -e napalm_username=admin -e napalm_password=... -e ansible_user=admin --ask-pass
```

The config playbooks target the **new lab's** groups only. The STIG-managed
switches converge through their own roles, and two toolchains pushing at the
same devices is how they end up fighting over the same lines. Read-only plays
cover everything, deliberately.

### Why these plays set both `connection: local` and `ansible_connection`

Every NAPALM playbook carries both:

```yaml
  connection: local
  vars:
    ansible_connection: local
    ansible_become: false
```

which looks redundant and is not. The `napalm_*` modules run on the controller,
so these plays should never touch a device's connection plugin — but inventory
sets `ansible_connection` per group (`network_cli` for the Cisco gear,
`netconf` for Juniper), and **an inventory variable outranks a play keyword**.
With only the keyword, every undelegated task in the play — `set_fact`,
`debug`, `assert` — still loads that group's connection plugin and its `become`
settings. Play vars outrank inventory group vars, so the `vars:` block is what
actually makes the play controller-only.

This was found by running the preflight play, not by reading: it failed on
`the connection plugin 'ansible.netcommon.netconf' was not found` at a
`set_fact` task, in a play that connects to nothing. Earlier test runs had
passed `-e ansible_connection=local`, which is extra-vars precedence and hid
the problem completely.

## Validating offline

```bash
python3 tests/run_offline.py          # 22 scenarios, no devices, no collections
python3 tests/run_offline.py -v       # ansible output for anything that fails
python3 tests/stub_devices.py /tmp/s  # just write the stubs, to poke at by hand
```

`tests/stub_devices.py` replaces every module the multi-vendor roles and
playbooks call with a script that accepts any arguments and returns plausible
data — the NAPALM getters come back shaped to exercise the interesting branches
rather than to describe a healthy device (a port enabled but down, one CPU core
pegged and one idle, a failed PSU, running ≠ startup). The module list is
discovered from the task files, so a new module gets a stub without editing
anything.

`tests/run_offline.py` then drives the real playbooks against those stubs and
asserts on what each run printed and wrote. Exit codes alone are not enough:
both bugs in the status section above exited 0 while being wrong. It skips
cleanly when `ansible-playbook` is not installed, like the suites in
[`../tests/`](../tests/).

What this cannot tell you is whether a device accepts what is sent, or whether a
module argument is spelled the way the installed collection expects — stubs
accept everything. That is what the lab is for.

## Safety, per platform

Each platform gets the strongest mechanism it actually has, which is not the
same mechanism:

| Platform | Mechanism | What it survives |
|---|---|---|
| Juniper | `commit confirmed <n>` | **A change that locks the controller out.** The timer runs on the switch; if the confirmation never arrives it reverts itself. Nothing restarts. |
| Palo Alto | candidate config, commit is opt-in | A half-finished run — edits sit in the candidate, in force nowhere, reviewable in the commit preview |
| Any NAPALM platform | dry-run diff (`napalm_commit=false`) | Pushing something you hadn't read |
| Cisco IOS | not saving startup-config | A lockout, via reload — see [`../docs/DESIGN.md`](../docs/DESIGN.md) |

`junos_safe_push` is the one push path here that is genuinely safe against
locking yourself out, and it is worth understanding why it is stronger than the
`reload in 5` net the `l2s_stig_harden_acl` role builds for IOS. Both fire
without connectivity, which is the property that matters. But a reload reverts
to the last *saved* configuration and bounces the device, so the whole
"never save config during a push" convention has to hold for it to work.
Junos reverts only that commit, and nothing reboots. The cycle is:

1. load, and read the switch's own `show | compare`
2. `commit confirmed 5`
3. drop the NETCONF session entirely
4. open a **new** one and prove it works
5. confirm, cancelling the timer

Step 3 is what makes step 4 mean anything — the same reasoning behind
`meta: reset_connection` in the AAA roles. The difference is the failure path:
on IOS that role is left with nothing to revert through and recovery is via
console; here the role deliberately does **nothing**, stops, and lets the
switch revert. There is no `rescue` block, because a rescue would have to reach
the device through the change that just broke access, and if it somehow did, it
might confirm a commit that should have been reverted.

## Credentials

Nothing is hardcoded and nothing secret is committed, matching the Python
side's convention:

- **NAPALM** (`napalm_username` / `napalm_password`) — prompted by each NAPALM
  playbook via `vars_prompt`, same pattern as `playbooks/stig_audit.yml`.
  Deliberately *not* defaulted in `group_vars`, so there is no file where a
  real password could end up.
- **Resource modules** — `-e ansible_user=admin --ask-pass`, as the STIG roles
  already do.
- **Palo Alto** — an API key in
  `inventory/group_vars/palo_alto/vault.yml` (gitignored; copy the `.example`,
  then `ansible-vault encrypt` it). Generate it against a dedicated admin
  account with a restricted role profile and permitted-IP list, not a
  superuser. The role refuses to run while it is `CHANGE_ME`.

Every committed file carries placeholders — `x.x.x.x`, `[]`, `""` — for the
same reason `inventory.yaml` is gitignored while `inventory.yaml.example` is
not. An empty value means "skip that feature", so a play run against this
repository as it stands configures *less* than it should rather than something
wrong. Addresses are stricter than that: a `x.x.x.x` placeholder reaching an
interface, a route or a firewall object is refused outright, because an unset
address is a skipped task while a placeholder address on a device is an outage.

## Controller requirements

```bash
pip install -r requirements.txt
ansible-galaxy collection install -r requirements-multivendor.yml
```

**This needs a newer `ansible-core` than the STIG roles' host can run**, and
that is the one real friction between the two toolchains in this directory.
The STIG automation host is Ubuntu 20.04 / Python 3.8, capped at
`ansible-core` 2.13.13, so `requirements.yml` holds it at `ansible.netcommon`
4.1.0 and `cisco.ios`/`cisco.nxos` 4.4.0. Every current collection in
`requirements-multivendor.yml` declares `requires_ansible >= 2.16`, and the
Junos and NX-OS collections need `ansible.netcommon` >= 8.1 and >= 8.6. **The
two sets cannot share one controller**: the netcommon pins exclude each other.
They were one file until 2026-09-13, and that file could not install anywhere.

The lab builds the multi-vendor controller next to the STIG toolchain without
touching it. `uv` downloads a standalone Python, since apt on 20.04 has
nothing newer than 3.8:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv venv --python 3.12 /opt/mv-ansible
uv pip install --python /opt/mv-ansible/bin/python -r requirements.txt
/opt/mv-ansible/bin/ansible-galaxy collection install \
    -r requirements-multivendor.yml -p /opt/mv-ansible/collections
export PATH=/opt/mv-ansible/bin:$PATH ANSIBLE_COLLECTIONS_PATH=/opt/mv-ansible/collections
```

What does not work is installing everything on the 2.13 host and trusting the
resolver. That is exactly how `ansible.netcommon` drifted and took every
network module down with it, the story in [`README.md`](README.md).

Per-platform prerequisites, each of which fails in a way that looks like
something else:

- **Juniper**: `set system services netconf ssh`. Both paths into these
  switches speak NETCONF, so without it nothing works while CLI SSH still
  does — which reads as a credentials problem.
- **NX-OS**: nothing. The `nxos_ssh` driver is used rather than `nxos`
  (NX-API) precisely so this layer does not silently require `feature nxapi`
  on a device before it can read anything.
- **Palo Alto**: an API key, and `pan-os-python` on the controller.
- **IOS**: nothing beyond SSH.

## What this closes, and what is next

Two items from the main [`README.md`](../README.md) roadmap:

- **Config push dry-run / diff-before-push** — `napalm_config_push` and
  `junos_safe_push`, both device-computed rather than string-compared.
- **Ansible playbook equivalents for core workflows** — backup, config diff,
  health check and fact collection now have multi-vendor Ansible paths
  alongside their Python counterparts.

### Verify on first contact with the lab

Offline validation cannot check these, and each is a place where a guess would
be silent rather than loud. In rough order of how much a wrong answer costs.
Items 1, 2, 3 and 5 were settled against JSW1 on 2026-09-13 (vJunos 26.2R1.7,
ansible-core 2.21.4, `napalm.napalm` 0.9.13, `junipernetworks.junos` 11.1.1):

1. **`napalm_validate`'s result key — SETTLED: `compliance_report`.** The
   installed module returns it as a top-level result key. The role used to fall
   back to `ansible_facts.napalm_validation_report` as well, which nothing
   returns, so that branch is gone, and the role still asserts a report came
   back at all. JSW1 came back COMPLIES.
2. **Getter coverage per driver — SETTLED for junos.** All ten getters in
   `group_vars/napalm_junos/vars.yml` answered on JSW1
   (`unsupported_getters: []`). The IOS and NX-OS lists are still from the
   support matrix, not from these devices.
3. **`junos_hostname` and `junos_ntp_global` schemas — SETTLED.** A real
   `junos_baseline` run committed through both, and an immediate `--check -D`
   re-run reported `changed=0`. `junos_logging_global` deliberately is still
   **not** used — syslog goes through `junos_config` set commands instead,
   because Junos requires a facility and severity on a host and the resource
   module's nested schema differs across collection versions. A guessed schema
   on a config push is what the `nxos_logging_global` history in
   [`README.md`](README.md) cost once.
4. **PAN-OS module arguments.** `panos_mgtconfig`, `panos_syslog_server`,
   `panos_interface`, `panos_security_rule`, `panos_static_route`,
   `panos_export` and `panos_commit_firewall` are all used with their common
   arguments; confirm against the installed collection's docs before the first
   real commit.
   `panos_export` specifically: the backup play fails if the exported file is
   under 1 KB rather than trusting that something was written, so a wrong
   argument there surfaces as a failed play rather than an empty backup.
5. **`--check` behaviour on Junos — SETTLED, and not what this said.** Each
   task really is a device operation: load the candidate, return the switch's
   own `show | compare`, roll back. JSW1's commit log confirmed that a failed
   check left nothing behind. But every task rolls back before the next one
   starts, so a task that depends on an earlier one cannot see it. On a switch
   without the VLANs, `--check` of `junos_baseline` fails at the trunk task:
   `vlan SERVERS configured under interface ge-0/0/0.0 does not exist`. So
   `--check -D` is **not** a usable first pass against a fresh switch. It is an
   excellent idempotency check once the baseline is in: after the real run it
   reported `changed=0` across all 15 tasks.

Also found on first contact, and not on the original list:

- **There is no `napalm.ansible` collection on Galaxy.** NAPALM's collection is
  `napalm.napalm`, and its modules keep their `napalm_` prefix
  (`napalm.napalm.napalm_get_facts`). Every role here called
  `napalm.ansible.*`, and the offline stubs registered the same wrong name, so
  `tests/run_offline.py` passed while no real run could have started.
- **`junipernetworks.junos` is deprecated in favour of `juniper.device`.**
  Every module still works through redirects, which are removed after
  2028-04-01, so each run prints a deprecation warning per task. Moving the
  Junos roles to `juniper.device.*` names is follow-up work, not a fault today.

### Then

- An NX-OS device in `nxos_lab` if one joins the lab; `cisco_baseline` already
  has the task file, and its NX-OS half encodes the three real differences
  (features before config, `mode: layer2` for a switchport, defaults absent
  from `show running-config`).
- `napalm_validate` expectations worth asserting once the lab has a known-good
  state: LLDP neighbours matching the intended topology would catch a
  miscabled uplink, which is the kind of thing no config audit sees.
- Whether the Palo Alto belongs in `napalm_panos` at all. Decide it by trying
  the driver, not by preference.
