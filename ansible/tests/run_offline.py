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


# Stand-in for inventory/group_vars/palo_alto_aws/vault.yml. 203.0.113.0/24 is
# TEST-NET-3 (RFC 5737), so the "public" address in these scenarios is
# documentation space rather than anyone's Elastic IP.
AWS_VAULT = {
    "vault_panos_aws_public_ip": "203.0.113.10",
    "vault_panos_aws_untrust_ip": "10.20.1.10/24",
    "vault_panos_aws_untrust_cidr": "10.20.1.0/24",
    "vault_panos_aws_untrust_gateway": "10.20.1.1",
    "vault_panos_aws_api_key": "stub-aws-key",
    "vault_lab_ipsec_psk": "stub-psk-value",
    "vault_lab_ike_identity": "r1.lab.local",
}


def scenarios(workdir):
    """(name, playbook, extra_vars, env, limit, expect_rc, must_contain, must_not_contain)."""
    out = str(workdir / "out")
    common = {"napalm_report_dir": out + "/reports", "napalm_backup_dir": out + "/backups"}

    def cisco(**over):
        return {**CISCO_VARS, **common, **over}

    return [
        # The regression test for the bug that reported every unreachable device
        # as READY, because `is succeeded` is true for a skipped task.
        # Mutation-tested: remove the `.skipped` guards in roles/preflight and
        # this fails.
        #
        # Every host is pointed at 192.0.2.1 - TEST-NET-1, unroutable by RFC
        # 5737 - rather than relying on the inventory's own addresses. Those are
        # real 10.10.50.x lab addresses now, and on a host whose network happens
        # to route 10/8 somewhere (a container in a cluster, say) a port check
        # SUCCEEDS and this test silently stops testing anything. Asserting on
        # row content rather than a "0/12" count also keeps it from breaking
        # every time a device is added to the lab.
        dict(name="preflight reports nothing ready when nothing can answer",
             playbook="preflight.yml",
             extra={**common, "napalm_username": "stub", "napalm_password": "stub",
                    "preflight_timeout": 1, "ansible_host": "192.0.2.1"},
             must_contain=["UNREACHABLE on port 830", "UNREACHABLE on port 443",
                           "UNREACHABLE on port 22", "NOT READY"],
             must_not_contain=["|  READY  |"]),

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
                           "CPU 91.0%", "RAM 75.0%", "temperature alerts: inlet",
                           "power/fan faults: PSU2"],
             # GigabitEthernet0/3 is shut, which is a decision rather than a
             # finding - see the role's note on V-220641a.
             must_not_contain=["GigabitEthernet0/3"]),

        dict(name="an unavailable counters getter is reported, not counted as clean",
             playbook="napalm_healthcheck.yml", limit="SW1", extra=cisco(),
             env={"STUB_UNSUPPORTED": "interfaces_counters,environment"},
             must_contain=["error counters NOT READ",
                           "has no usable environment getter"],
             must_not_contain=["over the 100-error/discard threshold", "CPU "]),

        dict(name="napalm_healthcheck gate fails on an environment finding alone",
             playbook="napalm_healthcheck.yml", limit="SW1",
             extra=cisco(napalm_healthcheck_fail=True, napalm_error_threshold=999999),
             expect_rc=2,
             # No interface passes the raised threshold, so a gate that only
             # looked at interfaces would pass this device despite PSU2, the
             # inlet alert and a pegged core.
             must_contain=["power/fan: PSU2", "temperature: inlet", "CPU 91.0%"]),

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

        # The regression test for a role-wide vendor default of "Cisco", which
        # asserted Cisco against the Juniper switches. The stub compares the
        # rendered intent against the vendor the device claims, so a wrong
        # expectation fails here rather than on a first live run.
        dict(name="napalm_validate expects Juniper on a Juniper switch",
             playbook="napalm_validate.yml", limit="JSW1",
             extra={**JUNOS_VARS, **common, "napalm_username": "stub",
                    "napalm_password": "stub"},
             env={"STUB_VENDOR": "Juniper"},
             must_contain=["JSW1: COMPLIES"]),

        dict(name="napalm_validate catches a wrong vendor expectation",
             playbook="napalm_validate.yml", limit="JSW1",
             extra={**JUNOS_VARS, **common, "napalm_username": "stub",
                    "napalm_password": "stub", "napalm_expected_vendor": "Cisco"},
             env={"STUB_VENDOR": "Juniper"}, expect_rc=2,
             must_contain=["DOES NOT COMPLY", "expected_value"]),

        dict(name="napalm_push dry run commits nothing",
             playbook="napalm_push.yml", limit="SW1",
             extra=cisco(napalm_config_template="example_ios.j2"),
             must_contain=["would change", "Dry run"],
             must_not_contain=["committed:"]),

        dict(name="napalm_push commits when told to",
             playbook="napalm_push.yml", limit="SW1",
             extra=cisco(napalm_config_template="example_ios.j2", napalm_commit=True),
             must_contain=["SW1 committed"], must_not_contain=["Dry run"]),

        # Renders R1's subinterfaces and HSRP. The exact-line assertions are the
        # regression test for a `{#-` whitespace-control bug that welded
        # "description", "encapsulation dot1Q 10" and "ip address ..." into a
        # single line - a config a router would reject, from a template whose
        # output contained every string anyone would have grepped for.
        dict(name="router_on_a_stick renders one command per line for R1",
             playbook="napalm_push.yml", limit="R1",
             extra={**common, "napalm_username": "stub", "napalm_password": "stub",
                    "napalm_config_template": "router_on_a_stick.j2",
                    "vault_hsrp_auth_key": "labkey123"},
             file_lines={out + "/reports/diffs/R1_candidate.cfg": [
                 "interface GigabitEthernet0/2.10",
                 "encapsulation dot1Q 10",
                 "ip address 10.0.10.2 255.255.255.0",
                 "standby 10 ip 10.0.10.1",
                 "standby 10 priority 110",
                 "standby 10 preempt",
                 "standby version 2",
                 "interface GigabitEthernet0/2.20",
                 "encapsulation dot1Q 20",
                 "ip address 10.0.20.2 255.255.255.0",
                 "standby 1 ip 10.0.1.4",
             ]}),

        # R2 must differ from R1 in exactly three ways: its address in each VLAN,
        # its HSRP priority, and which switch it trunks to. Equal priorities
        # would elect by IP address instead - which works, is silent, and is not
        # what the design says.
        dict(name="R2 renders as the standby half of the pair",
             playbook="napalm_push.yml", limit="R2",
             extra={**common, "napalm_username": "stub", "napalm_password": "stub",
                    "napalm_config_template": "router_on_a_stick.j2",
                    "vault_hsrp_auth_key": "labkey123"},
             file_lines={out + "/reports/diffs/R2_candidate.cfg": [
                 "ip address 10.0.10.3 255.255.255.0",
                 "ip address 10.0.20.3 255.255.255.0",
                 "standby 10 priority 100",
                 "standby 20 priority 100",
                 "description trunk to SW2 - VLAN subinterfaces below",
             ]},
             file_lines_absent={out + "/reports/diffs/R2_candidate.cfg": [
                 "standby 10 priority 110",
                 "ip address 10.0.10.2 255.255.255.0",
             ]}),

        # An unset HSRP key must omit authentication entirely rather than send an
        # empty or placeholder key-string, which IOS would take literally.
        dict(name="HSRP authentication is omitted when no key is vaulted",
             playbook="napalm_push.yml", limit="R1",
             extra={**common, "napalm_username": "stub", "napalm_password": "stub",
                    "napalm_config_template": "router_on_a_stick.j2",
                    "vault_hsrp_auth_key": "CHANGE_ME"},
             file_lines_absent={out + "/reports/diffs/R1_candidate.cfg": [
                 "standby 10 authentication md5 key-string CHANGE_ME",
                 "standby 10 authentication md5 key-string",
             ]}),

        # The hybrid scenario. Both ends read one set of crypto variables, so the
        # assertions check that the router's rendered config carries the values
        # the firewall is configured with - a tunnel whose ends disagree about a
        # proposal is the failure this shape exists to prevent.
        dict(name="site_to_site_vpn renders R1's end from the firewall's own vars",
             playbook="napalm_push.yml", limit="R1",
             extra={**common, **AWS_VAULT, "napalm_username": "stub",
                    "napalm_password": "stub",
                    "napalm_config_template": "site_to_site_vpn.j2"},
             file_lines={out + "/reports/diffs/R1_candidate.cfg": [
                 "address 203.0.113.10",
                 "pre-shared-key stub-psk-value",
                 "identity local fqdn r1.lab.local",
                 "match identity remote address 203.0.113.10 255.255.255.255",
                 "tunnel mode ipsec ipv4",
                 "tunnel destination 203.0.113.10",
                 "tunnel protection ipsec profile AWS-IPSEC",
                 "ip address 169.254.1.2 255.255.255.252",
                 "ip tcp adjust-mss 1379",
                 "ip route 10.20.1.0 255.255.255.0 Tunnel1",
             ]},
             # The guard is the point: a default route into a tunnel that is not
             # up replaces a working route with a black hole, so it must take a
             # second explicit flag.
             file_lines_absent={out + "/reports/diffs/R1_candidate.cfg": [
                 "ip route 0.0.0.0 0.0.0.0 Tunnel1",
             ]}),

        dict(name="lab egress moves to the tunnel only when explicitly asked",
             playbook="napalm_push.yml", limit="R1",
             extra={**common, **AWS_VAULT, "napalm_username": "stub",
                    "napalm_password": "stub",
                    "napalm_config_template": "site_to_site_vpn.j2",
                    "vpn_default_via_tunnel": True},
             file_lines={out + "/reports/diffs/R1_candidate.cfg": [
                 "ip route 0.0.0.0 0.0.0.0 Tunnel1",
             ]}),

        # The claim this scenario exists to check: panos_baseline is the same role
        # for a firewall in AWS as for one in the lab, and only inventory differs.
        # The AWS firewall's routes point down the tunnel and its untrust address
        # comes from the vault, neither of which the local firewall has.
        # verbose_run because the tunnel next hop and interface are module
        # ARGUMENTS - they appear in a task result, not in the play's output.
        dict(name="panos_baseline configures the AWS firewall from its own vars",
             playbook="panos_baseline.yml", limit="PA-AWS", verbose_run=True,
             extra={**common, **AWS_VAULT},
             must_contain=["10.20.1.10/24", "169.254.1.2", "tunnel.1",
                           "staged but not committed"]),

        dict(name="panos_vpn stages the tunnel without committing it",
             playbook="hybrid_vpn.yml", extra={**common, **AWS_VAULT},
             must_contain=["staged but not committed",
                           "Configure the IKE gateway",
                           "Configure the IPsec tunnel"],
             must_not_contain=["ok: [PA-AWS] => (item=commit"]),

        dict(name="panos_vpn refuses to run without a PSK or peer identity",
             playbook="hybrid_vpn.yml",
             extra={**common, **{**AWS_VAULT, "vault_lab_ipsec_psk": "CHANGE_ME"}},
             expect_rc=2,
             must_contain=["peer ID is not optional"]),

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
        # --limit PA1 because panos_baseline.yml targets the whole palo_alto
        # group, which now also holds the AWS firewall - these two are about the
        # LOCAL firewall's gates, and the fixture only carries its vault.
        dict(name="panos_baseline stages without committing and keeps policy shut",
             playbook="panos_baseline.yml", limit="PA1",
             extra={**PANOS_VARS, **common},
             must_contain=["PA-440", "PAN-OS 11.1.2", "NOT in force",
                           "skipping: [PA1] => (item=users-out"],
             must_not_contain=["ok: [PA1] => (item=users-out"]),

        dict(name="panos_baseline pushes policy and commits when both gates are set",
             playbook="panos_baseline.yml", limit="PA1",
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

    # Exact-line assertions on a rendered file. Needed because a template bug can
    # produce a file that contains every expected substring while being useless:
    # Jinja's `{#-` whitespace control welded three config commands onto one line
    # here, which a substring check passes and a router rejects.
    for path, expected in (scenario.get("file_lines") or {}).items():
        if not pathlib.Path(path).exists():
            problems.append(f"never written: {path}")
            continue
        lines = [line.strip() for line in pathlib.Path(path).read_text().splitlines()]
        for line in expected:
            if line not in lines:
                problems.append(f"{pathlib.Path(path).name}: no line reading {line!r}")
    for path, unexpected in (scenario.get("file_lines_absent") or {}).items():
        if pathlib.Path(path).exists():
            lines = [line.strip() for line in pathlib.Path(path).read_text().splitlines()]
            for line in unexpected:
                if line in lines:
                    problems.append(f"{pathlib.Path(path).name}: unwanted line {line!r}")

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
