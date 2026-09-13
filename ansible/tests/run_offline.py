#!/usr/bin/env python3
"""Run every multi-vendor play offline against stub devices and check what it did.

    python3 ansible/tests/run_offline.py
    python3 ansible/tests/run_offline.py -v      # show ansible output for failures

No devices, no credentials, no collections: stub_devices.py replaces every
module the roles call, and this drives the real playbooks against them. What is
under test is everything between the inventory and the module call - the Jinja,
the conditionals, the asserts, the gates that are supposed to stay shut.

Each scenario asserts on what the run PRINTED or WROTE, not just its exit code.
Both bugs recorded in NAPALM.md's status section exited 0 while being wrong, so
a passing run has to be checked for the right content:

  - preflight against twelve placeholder addresses must say 0/12 ready, not
    12/12 (a skipped check counted as a passed one)
  - a non-compliant device must FAIL the validate play (so a report that never
    arrives cannot read as a pass)
  - an unsupported getter must be named, and must not take the gather with it
  - the dry-run and opt-in gates must produce no commit unless asked

Requires ansible-core on PATH and skips cleanly without it, so it behaves like
the suites in ../../tests/ - runnable on a fresh clone with nothing configured.
"""

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import stub_devices  # noqa: E402

ANSIBLE_DIR = pathlib.Path(__file__).resolve().parent.parent

# Device data covering every shape the roles consume. Addresses are RFC 1918
# and go nowhere: no play in this file reaches the network, since the port
# checks target placeholder hosts and every module is a stub.
CISCO_VARS = {
    "napalm_username": "stub",
    "napalm_password": "stub",
    "baseline_domain_name": "lab.local",
    "baseline_vlans": [{"vlan_id": 10, "name": "USERS"}, {"vlan_id": 20, "name": "VOICE"}],
    "baseline_access_ports": [
        {"name": "GigabitEthernet0/2", "vlan": 10, "description": "user port"},
        {"name": "GigabitEthernet0/3", "vlan": 20},
    ],
    "baseline_trunk_ports": [
        {"name": "GigabitEthernet0/1", "description": "uplink",
         "allowed_vlans": [10, 20], "native_vlan": 999},
    ],
    "baseline_l3_interfaces": [{"name": "Vlan10", "ipv4_cidr": "10.0.10.1/24"}],
    "baseline_static_routes": [{"dest": "10.9.0.0/24", "next_hop": "10.0.10.254"}],
    "baseline_ospf": {"process_id": 1, "router_id": "1.1.1.1",
                      "networks": [{"address": "10.0.10.0", "wildcard_bits": "0.0.0.255",
                                    "area": 0}]},
    "baseline_ntp_servers": ["10.0.0.10", "10.0.0.11"],
    "baseline_syslog_servers": ["10.0.0.20"],
    "napalm_expected_up_interfaces": ["GigabitEthernet0/1"],
}

JUNOS_VARS = {
    "baseline_domain_name": "lab.local",
    "baseline_vlans": [{"name": "USERS", "vlan_id": 10}],
    # VLAN by NAME, which is the Junos shape - see group_vars/juniper_switches.
    "baseline_access_ports": [{"name": "ge-0/0/2", "vlan": "USERS", "description": "user port"}],
    "baseline_trunk_ports": [{"name": "ge-0/0/0", "description": "uplink",
                              "allowed_vlans": ["USERS"], "native_vlan": 999}],
    "baseline_l3_interfaces": [{"name": "irb", "unit": 10, "ipv4_cidr": "10.0.10.2/24"}],
    "baseline_static_routes": [{"dest": "10.9.0.0/24", "next_hop": "10.0.10.254"}],
    "baseline_ntp_servers": ["10.0.0.10"],
    "baseline_syslog_servers": ["10.0.0.20"],
    "baseline_lldp_enabled": True,
}

PANOS_VARS = {
    "vault_panos_api_key": "stub-api-key",
    "baseline_timezone": "US/Eastern",
    "baseline_ntp_servers": ["10.0.0.10", "10.0.0.11"],
    "baseline_syslog_servers": ["10.0.0.20"],
    "baseline_zones": [{"name": "trust", "mode": "layer3", "interfaces": ["ethernet1/2"]},
                       {"name": "untrust", "mode": "layer3", "interfaces": ["ethernet1/1"]}],
    "baseline_interfaces": [{"name": "ethernet1/2", "ipv4_cidr": "10.0.1.1/24",
                             "zone": "trust", "comment": "inside"}],
    "baseline_address_objects": [{"name": "LAN_USERS", "value": "10.0.10.0/24"}],
    "baseline_security_rules": [{"name": "users-out", "source_zone": ["trust"],
                                 "destination_zone": ["untrust"], "source_ip": ["LAN_USERS"],
                                 "destination_ip": ["any"], "application": ["ssl"]}],
    "baseline_static_routes": [{"name": "default", "destination": "0.0.0.0/0",
                                "nexthop": "10.0.0.254", "interface": "ethernet1/1"}],
}


def scenarios(workdir):
    """(name, playbook, extra_vars, env, limit, expect_rc, must_contain, must_not_contain)."""
    out = str(workdir / "out")
    common = {"napalm_report_dir": out + "/reports", "napalm_backup_dir": out + "/backups"}

    def cisco(**over):
        return {**CISCO_VARS, **common, **over}

    return [
        # The regression test for the bug that reported every unreachable device
        # as READY, because `is succeeded` is true for a skipped task. Inventory
        # ships x.x.x.x placeholders, so nothing can answer. Mutation-tested:
        # remove the `.skipped` guards in roles/preflight and this fails.
        dict(name="preflight reports nothing ready against placeholder addresses",
             playbook="preflight.yml",
             extra={**common, "napalm_username": "stub", "napalm_password": "stub",
                    "preflight_timeout": 1},
             must_contain=["0/12 ready", "UNREACHABLE on port 830",
                           "UNREACHABLE on port 443", "NOT READY"],
             must_not_contain=["12/12 ready", "READY  |"]),

        dict(name="napalm_facts collects and summarises a device",
             playbook="napalm_facts.yml", limit="SW1", extra=cisco(),
             must_contain=["Cisco WS-C3850-24T", "os 16.12.4", "3 interfaces"]),

        dict(name="an unsupported getter is named and does not lose the gather",
             playbook="napalm_facts.yml", limit="SW1", extra=cisco(),
             env={"STUB_UNSUPPORTED": "environment,mac_address_table"},
             must_contain=["did not answer", "environment", "Cisco WS-C3850-24T"]),

        dict(name="napalm_healthcheck finds the down port, errors, hot inlet and dead PSU",
             playbook="napalm_healthcheck.yml", limit="SW1", extra=cisco(),
             must_contain=["1 enabled-but-down", "GigabitEthernet0/2",
                           "CPU 91.0%", "temperature alerts: inlet",
                           "power/fan faults: PSU2"],
             # GigabitEthernet0/3 is shut, which is a decision rather than a
             # finding - see the role's note on V-220641a.
             must_not_contain=["GigabitEthernet0/3"]),

        dict(name="napalm_backup writes a backup and notices running != startup",
             playbook="napalm_backup.yml", limit="SW1", extra=cisco(),
             must_contain=["differs from startup-config"],
             writes=[out + "/backups/SW1.cfg"]),

        dict(name="napalm_validate passes a compliant device",
             playbook="napalm_validate.yml", limit="SW1", extra=cisco(),
             must_contain=["SW1: COMPLIES"],
             writes=[out + "/reports/compliance/SW1_report.json"]),

        dict(name="napalm_validate FAILS a non-compliant device",
             playbook="napalm_validate.yml", limit="SW1", extra=cisco(),
             env={"STUB_COMPLIES": "false"}, expect_rc=2,
             must_contain=["DOES NOT COMPLY", "does not match declared state"]),

        dict(name="napalm_push dry run commits nothing",
             playbook="napalm_push.yml", limit="SW1",
             extra=cisco(napalm_config_template="example_ios.j2"),
             must_contain=["would change", "Dry run"],
             must_not_contain=["committed:"]),

        dict(name="napalm_push commits when told to",
             playbook="napalm_push.yml", limit="SW1",
             extra=cisco(napalm_config_template="example_ios.j2", napalm_commit=True),
             must_contain=["SW1 committed"], must_not_contain=["Dry run"]),

        dict(name="cisco_baseline assembles every domain for switches and a router",
             playbook="cisco_baseline.yml", extra=cisco(ansible_connection="local",
                                                        ansible_become=False),
             must_contain=["Configure VLANs", "Configure access and trunk ports",
                           "Configure static routes", "Configure OSPFv2"]),

        # verbose_run because the syslog assertion is about the set command the
        # module was CALLED with, which only appears in a task result.
        dict(name="junos_baseline assembles VLANs by name and irb units",
             playbook="junos_baseline.yml", limit="JSW1", verbose_run=True,
             extra={**JUNOS_VARS, **common, "ansible_connection": "local"},
             must_contain=["ge-0/0/2 -> vlan USERS", "irb.10 10.0.10.2/24",
                           "set system syslog host 10.0.0.20 any notice"]),

        dict(name="junos_safe_push dry run rolls back and commits nothing",
             playbook="junos_safe_push.yml", limit="JSW1",
             extra={**JUNOS_VARS, **common, "ansible_connection": "local",
                    "junos_config_template": "example_junos.j2"},
             must_contain=["Dry run", "rolled", "commit confirmed 5"],
             writes=[out + "/reports/diffs/JSW1_candidate.conf"]),

        dict(name="junos_safe_push confirms only after proving a new connection",
             playbook="junos_safe_push.yml", limit="JSW1",
             extra={**JUNOS_VARS, **common, "ansible_connection": "local",
                    "junos_config_template": "example_junos.j2", "junos_commit": True},
             must_contain=["Commit confirmed 5", "Prove a brand-new connection",
                           "Confirm the commit"]),

        # These two assert on the per-item result lines rather than on task
        # names: a skipped loop still prints its item label, and a skipped task
        # still prints its name, so "users-out" and "staged but not committed"
        # both appear either way. Only "skipping: ... (item=" vs "ok: ... (item="
        # distinguishes a gate that held from one that did not.
        dict(name="panos_baseline stages without committing and keeps policy shut",
             playbook="panos_baseline.yml", extra={**PANOS_VARS, **common},
             must_contain=["PA-440", "PAN-OS 11.1.2", "NOT in force",
                           "skipping: [PA1] => (item=users-out"],
             must_not_contain=["ok: [PA1] => (item=users-out"]),

        dict(name="panos_baseline pushes policy and commits when both gates are set",
             playbook="panos_baseline.yml",
             extra={**PANOS_VARS, **common, "push_security_rules": True,
                    "panos_commit": True},
             must_contain=["ok: [PA1] => (item=users-out"],
             must_not_contain=["NOT in force"]),
    ]


def run(scenario, workdir, stub_path, verbose):
    extra = dict(scenario.get("extra") or {})
    var_file = workdir / "vars.json"
    var_file.write_text(json.dumps(extra))

    cmd = ["ansible-playbook", f"playbooks/{scenario['playbook']}",
           "-e", f"@{var_file}"]
    # -v prints each task's result, which is the only way to assert on the
    # arguments a module was CALLED with rather than on what the play printed.
    if scenario.get("verbose_run"):
        cmd.append("-v")
    if scenario.get("limit"):
        cmd += ["--limit", scenario["limit"]]

    env = {**os.environ,
           "ANSIBLE_COLLECTIONS_PATH": str(stub_path),
           "ANSIBLE_STDOUT_CALLBACK": "default",
           "ANSIBLE_FORCE_COLOR": "0",
           **(scenario.get("env") or {})}

    proc = subprocess.run(cmd, cwd=ANSIBLE_DIR, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    output = proc.stdout
    problems = []

    expect_rc = scenario.get("expect_rc", 0)
    if proc.returncode != expect_rc:
        problems.append(f"exit {proc.returncode}, expected {expect_rc}")
    for needle in scenario.get("must_contain", []):
        if needle not in output:
            problems.append(f"missing from output: {needle!r}")
    for needle in scenario.get("must_not_contain", []):
        if needle in output:
            problems.append(f"should not appear in output: {needle!r}")
    for path in scenario.get("writes", []):
        if not pathlib.Path(path).exists():
            problems.append(f"never written: {path}")

    if problems and verbose:
        print(output)
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print ansible output for failing scenarios")
    parser.add_argument("-k", "--keep", action="store_true",
                        help="keep the stub tree and run output for inspection")
    args = parser.parse_args()

    if shutil.which("ansible-playbook") is None:
        print("SKIP: ansible-playbook not on PATH. "
              "pip install -r requirements.txt to run this suite.")
        return 0

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="netauto-offline-"))
    stub_path = workdir / "collections"
    modules = stub_devices.write_stubs(ANSIBLE_DIR, stub_path)
    print(f"stubbed {len(modules)} modules -> {stub_path}")

    failures = 0
    try:
        for scenario in scenarios(workdir):
            problems = run(scenario, workdir, stub_path, args.verbose)
            if problems:
                failures += 1
                print(f"FAIL  {scenario['name']}")
                for problem in problems:
                    print(f"        {problem}")
            else:
                print(f"ok    {scenario['name']}")
    finally:
        if args.keep:
            print(f"kept: {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)

    print()
    if failures:
        print(f"{failures} scenario(s) failed. Re-run with -v for the ansible output.")
        return 1
    print("all scenarios passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
