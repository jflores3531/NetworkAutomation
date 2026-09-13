#!/usr/bin/env python3
"""Generate stub Ansible modules so the multi-vendor plays can be run offline.

Every module the roles call is replaced by a script that accepts whatever
arguments it is given and returns a plausible result. The plays then execute
for real - every Jinja expression, every conditional, every assert - with no
device, no credentials and no collections installed.

Why this exists rather than relying on --syntax-check and review: two bugs in
this directory were silent false passes that both of those missed, and running
the plays is what found them. Both are regression-tested by run_offline.py,
which drives this module:

  1. `is succeeded` is true for a SKIPPED task, so a check that never ran read
     identically to one that passed - which made every unreachable device
     report READY
  2. an inventory `ansible_connection` outranks a play's `connection:` keyword,
     so plays meant to run on the controller were still loading each group's
     network_cli/netconf plugin

Both exited 0 while being wrong, which is why the scenarios in run_offline.py
assert on output and written files rather than on exit codes.

What it cannot tell you: whether a real device accepts what is sent, or whether
a module argument is spelled the way the installed collection expects. Stubs
accept everything. See ../NAPALM.md, "Verify on first contact with the lab".

Modules are discovered from the role task files rather than listed here, so a
new module in a role gets a stub without this file changing.
"""

import pathlib
import re
import stat

# Roles and playbooks whose modules get stubbed. The STIG ones are excluded
# deliberately: they are a separate, live-tested toolchain, and pointing a stub
# collection path at them would only prove that stubs return what stubs return.
#
# Playbooks are scanned as well as roles because a few tasks live directly in a
# play - the Palo Alto config export in napalm_backup.yml is one - and the first
# version of this file missed them, which run_offline.py caught as an
# unresolvable module rather than a wrong result.
MULTIVENDOR_ROLES = (
    "preflight",
    "napalm_facts",
    "napalm_healthcheck",
    "napalm_backup",
    "napalm_validate",
    "napalm_config_push",
    "cisco_baseline",
    "junos_baseline",
    "junos_safe_push",
    "panos_baseline",
    "fortigate_baseline",
    "fortiswitch_baseline",
)

MULTIVENDOR_PLAYBOOKS = (
    "preflight.yml",
    "napalm_facts.yml",
    "napalm_healthcheck.yml",
    "napalm_backup.yml",
    "napalm_validate.yml",
    "napalm_push.yml",
    "cisco_baseline.yml",
    "junos_baseline.yml",
    "junos_safe_push.yml",
    "panos_baseline.yml",
    "fortinet_baseline.yml",
)

# Module names written as a task's action, e.g. `cisco.ios.ios_vlans:`.
FQCN_RE = re.compile(r"^\s{2,}([a-z0-9_]+)\.([a-z0-9_]+)\.([a-z0-9_]+):\s*$", re.M)

# ansible.builtin ships with ansible-core and must never be stubbed - doing so
# would replace set_fact, assert, copy and debug, i.e. the parts of the roles
# actually under test.
NEVER_STUB = {"ansible", "ansible.builtin", "ansible.netcommon", "ansible.utils"}

GENERIC = '''#!/usr/bin/python
# WANT_JSON
"""Stub: accepts any arguments, reports no change, echoes what it received."""
import json
import sys

with open(sys.argv[1]) as fh:
    params = json.load(fh)
print(json.dumps({
    "changed": False,
    "stub_received": {k: v for k, v in params.items() if not k.startswith("_ansible")},
}))
'''

# Canned NAPALM getter output. Shaped to exercise the interesting branches
# rather than to describe a healthy device: GigabitEthernet0/2 is enabled but
# down AND over the error threshold, one CPU core is pegged while the other is
# idle (so an averaging bug shows up), PSU2 has failed, the inlet temperature
# is alerting, and running differs from startup.
NAPALM_GET_FACTS = '''#!/usr/bin/python
# WANT_JSON
"""Stub napalm_get_facts. STUB_UNSUPPORTED=a,b makes those getters fail, the
way a driver that does not implement them does."""
import json
import os
import sys

with open(sys.argv[1]) as fh:
    params = json.load(fh)
getter = params.get("filter", "facts")

CANNED = {
    "facts": {
        "hostname": "stub-device", "fqdn": "stub-device.lab", "vendor": "Cisco",
        "model": "WS-C3850-24T", "serial_number": "FOC1234X56Y",
        "os_version": "16.12.4", "uptime": 987654,
        "interface_list": ["GigabitEthernet0/1", "GigabitEthernet0/2", "Vlan10"],
    },
    "interfaces": {
        "GigabitEthernet0/1": {"is_up": True, "is_enabled": True, "description": "uplink",
                               "last_flapped": -1.0, "speed": 1000, "mtu": 1500,
                               "mac_address": "00:11:22:33:44:55"},
        "GigabitEthernet0/2": {"is_up": False, "is_enabled": True, "description": "user port",
                               "last_flapped": -1.0, "speed": 1000, "mtu": 1500,
                               "mac_address": "00:11:22:33:44:56"},
        "GigabitEthernet0/3": {"is_up": False, "is_enabled": False, "description": "spare",
                               "last_flapped": -1.0, "speed": 0, "mtu": 1500,
                               "mac_address": "00:11:22:33:44:57"},
    },
    "interfaces_ip": {"Vlan10": {"ipv4": {"10.0.10.1": {"prefix_length": 24}}}},
    "interfaces_counters": {
        "GigabitEthernet0/1": {"rx_errors": 0, "tx_errors": 0, "rx_discards": 0, "tx_discards": 0},
        "GigabitEthernet0/2": {"rx_errors": 5000, "tx_errors": 12, "rx_discards": 3, "tx_discards": 0},
    },
    "lldp_neighbors": {"GigabitEthernet0/1": [{"hostname": "R1", "port": "Gi0/0"}]},
    "arp_table": [{"interface": "Vlan10", "mac": "00:11:22:33:44:60",
                   "ip": "10.0.10.50", "age": 12.0}],
    "mac_address_table": [{"mac": "00:11:22:33:44:60", "interface": "Gi0/2", "vlan": 10,
                           "static": False, "active": True, "moves": 1, "last_move": 0.0}],
    "ntp_servers": {"10.0.0.10": {}, "10.0.0.11": {}},
    "users": {"admin": {"level": 15, "password": "", "sshkeys": []}},
    "optics": {},
    "environment": {
        "cpu": {"0": {"%usage": 17.5}, "1": {"%usage": 91.0}},
        "memory": {"available_ram": 1048576, "used_ram": 3145728},
        "temperature": {"chassis": {"temperature": 41.0, "is_alert": False, "is_critical": False},
                        "inlet": {"temperature": 78.0, "is_alert": True, "is_critical": False}},
        "power": {"PSU1": {"status": True, "capacity": 715.0, "output": 100.0},
                  "PSU2": {"status": False, "capacity": 0.0, "output": 0.0}},
        "fans": {"FAN1": {"status": True}},
    },
    "config": {"running": "hostname stub-device\\n!\\nntp server 10.0.0.10\\n",
               "startup": "hostname stub-device\\n", "candidate": ""},
}

unsupported = [g for g in os.environ.get("STUB_UNSUPPORTED", "").split(",") if g]
if getter in unsupported:
    print(json.dumps({"failed": True,
                      "msg": "stub: driver does not implement get_%s" % getter}))
    sys.exit(1)

print(json.dumps({"changed": False,
                  "ansible_facts": {"napalm_%s" % getter: CANNED.get(getter, {})}}))
'''

NAPALM_VALIDATE = '''#!/usr/bin/python
# WANT_JSON
"""Stub napalm_validate. STUB_COMPLIES=false reports non-compliance, so the
role's fail path is exercised rather than assumed."""
import json
import os
import sys

with open(sys.argv[1]) as fh:
    json.load(fh)
complies = os.environ.get("STUB_COMPLIES", "true") == "true"
print(json.dumps({"changed": False, "compliance_report": {
    "complies": complies,
    "get_facts": {"complies": complies, "missing": [], "extra": [],
                  "present": {"vendor": {"complies": complies, "nested": False,
                                         "actual_value": "Cisco"}}},
    "skipped": [],
}}))
'''

NAPALM_INSTALL_CONFIG = '''#!/usr/bin/python
# WANT_JSON
"""Stub napalm_install_config. Reads the rendered candidate off disk so the
diff reflects whether the template produced anything."""
import json
import os
import sys

with open(sys.argv[1]) as fh:
    params = json.load(fh)
body = ""
path = params.get("config_file")
if path and os.path.exists(path):
    with open(path) as fh:
        body = fh.read()
diff = "+ntp server 10.0.0.10\\n+lldp run" if body.strip() else ""
if params.get("diff_file"):
    with open(params["diff_file"], "w") as fh:
        fh.write(diff)
print(json.dumps({"changed": bool(diff) and bool(params.get("commit_changes")),
                  "diff": {"prepared": diff},
                  "stub_rendered_bytes": len(body)}))
'''

PANOS_FACTS = '''#!/usr/bin/python
# WANT_JSON
import json
import sys

with open(sys.argv[1]) as fh:
    json.load(fh)
print(json.dumps({"changed": False, "ansible_facts": {
    "ansible_net_model": "PA-440", "ansible_net_version": "11.1.2",
    "ansible_net_serial": "0123456789", "ansible_net_hostname": "PA1"}}))
'''

PANOS_EXPORT = '''#!/usr/bin/python
# WANT_JSON
"""Stub panos_export. Writes a file large enough to pass the backup play's
minimum-size guard, since that guard is part of what is being tested."""
import json
import sys

with open(sys.argv[1]) as fh:
    params = json.load(fh)
if params.get("filename"):
    with open(params["filename"], "w") as fh:
        fh.write("<config>\\n" + ("  <entry>stub</entry>\\n" * 200) + "</config>\\n")
print(json.dumps({"changed": True}))
'''

FORTIOS_MONITOR_FACT = '''#!/usr/bin/python
# WANT_JSON
import json
import sys

with open(sys.argv[1]) as fh:
    params = json.load(fh)
selector = (params.get("selectors") or [{}])[0].get("selector", "")
if selector == "system_config_backup":
    meta = {"raw": "#config-version=FGT\\nconfig system global\\nend\\n" * 10}
else:
    meta = {"results": {"version": "v7.4.4", "serial": "FGT60FTK00000000"}}
print(json.dumps({"changed": False, "meta": meta}))
'''

SPECIAL = {
    "napalm.ansible.napalm_get_facts": NAPALM_GET_FACTS,
    "napalm.ansible.napalm_validate": NAPALM_VALIDATE,
    "napalm.ansible.napalm_install_config": NAPALM_INSTALL_CONFIG,
    "paloaltonetworks.panos.panos_facts": PANOS_FACTS,
    "paloaltonetworks.panos.panos_export": PANOS_EXPORT,
    "fortinet.fortios.fortios_monitor_fact": FORTIOS_MONITOR_FACT,
}


def discover_modules(ansible_dir):
    """Every FQCN module used by the multi-vendor roles and playbooks."""
    sources = [f for role in MULTIVENDOR_ROLES
               for f in sorted((ansible_dir / "roles" / role).rglob("*.yml"))]
    sources += [ansible_dir / "playbooks" / name for name in MULTIVENDOR_PLAYBOOKS]

    found = set()
    for source in sources:
        for namespace, collection, module in FQCN_RE.findall(source.read_text()):
            if namespace in NEVER_STUB or f"{namespace}.{collection}" in NEVER_STUB:
                continue
            found.add(f"{namespace}.{collection}.{module}")
    return sorted(found)


def write_stubs(ansible_dir, target):
    """Write a stub collection tree under target. Returns the module list."""
    modules = discover_modules(ansible_dir)
    for fqcn in modules:
        namespace, collection, module = fqcn.split(".")
        path = target / "ansible_collections" / namespace / collection / "plugins" / "modules"
        path.mkdir(parents=True, exist_ok=True)
        module_file = path / f"{module}.py"
        module_file.write_text(SPECIAL.get(fqcn, GENERIC))
        module_file.chmod(module_file.stat().st_mode | stat.S_IEXEC)
    return modules


if __name__ == "__main__":
    import sys
    here = pathlib.Path(__file__).resolve().parent
    out = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else here / "stubs"
    written = write_stubs(here.parent, out)
    print(f"{len(written)} stub modules written to {out}")
    for name in written:
        print(" ", name)
