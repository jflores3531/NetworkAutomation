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

## Status: validated offline, never run against hardware

**Nothing here has touched a real device.** This repository's convention is to
say so plainly (see the "confirmed working live" sections in
[`README.md`](README.md), each of which names the device and date), so:

What *has* been done — every playbook and role executed end to end against stub
modules returning realistic device data, on the controller, with these results:

- all 14 playbooks pass `--syntax-check`
- `ansible/tests/run_offline.py` drives all of it as 15 scenarios and asserts on
  what each run printed and wrote, not just its exit code — every one of the
  bugs below exited 0 while being wrong. The suite is mutation-tested: breaking
  the fix again fails it
- `preflight` reports per-device readiness across 12 devices without aborting,
  and distinguishes unreachable / port-open-login-failed / NETCONF-not-enabled —
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
python3 tests/run_offline.py          # 15 scenarios, no devices, no collections
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
ansible-galaxy collection install -r requirements.yml
```

**This needs a newer `ansible-core` than the STIG roles' host can run**, and
that is the one real friction between the two toolchains in this directory.
`requirements.yml` pins `cisco.ios`/`cisco.nxos` to 4.4.0 because the STIG
automation host is Ubuntu 20.04 / Python 3.8, capped at `ansible-core`
2.13.13 — while current `paloaltonetworks.panos` and `junipernetworks.junos`
releases declare `requires_ansible >= 2.15`. Either run the multi-vendor plays
from a host with a current `ansible-core`, or keep both on one machine in
separate virtualenvs. What does not work is installing everything on the 2.13
host and trusting the resolver — that is exactly how `ansible.netcommon`
drifted and took every network module down with it, the story in
[`README.md`](README.md).

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
be silent rather than loud. In rough order of how much a wrong answer costs:

1. **`napalm_validate`'s result key.** The role accepts either
   `compliance_report` or `ansible_facts.napalm_validation_report` because the
   module has moved it between versions, and asserts that a report came back at
   all. Confirm which one the installed collection uses and delete the other —
   an expression that silently fell through to `{}` would report every device
   compliant.
2. **Getter coverage per driver.** The getter lists in
   `group_vars/napalm_*/vars.yml` are from the support matrix, not from these
   devices. Anything unsupported is named in the run output; move it out of the
   list once you know.
3. **`junos_hostname` and `junos_ntp_global` schemas.** Both are used here;
   `junos_logging_global` deliberately is **not** — syslog goes through
   `junos_config` set commands instead, because Junos requires a facility and
   severity on a host and the resource module's nested schema differs across
   collection versions. A guessed schema on a config push is what the
   `nxos_logging_global` history in [`README.md`](README.md) cost once.
4. **PAN-OS module arguments.** `panos_mgtconfig`, `panos_syslog_server`,
   `panos_interface`, `panos_security_rule`, `panos_static_route`,
   `panos_export` and `panos_commit_firewall` are all used with their common
   arguments; confirm against the installed collection's docs before the first
   real commit.
5. **`--check` behaviour on Junos.** Check mode there is a real device
   operation — load the candidate, return `show | compare`, roll back — so
   `--check -D` is more truthful on the Juniper switches than on anything else
   in this repository. Confirm that, then use it as the default first pass.
6. **`panos_export`'s output.** The backup play fails if the exported file is
   under 1 KB rather than trusting that something was written.

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
