#!/usr/bin/env python
"""Verification for scripts/yaml.py.

Run directly: `python3 tests/test_yaml_parser.py`. No framework, no device.

scripts/yaml.py shadows an installed PyYAML for everything run out of
scripts/, so it is not a fallback that only locked-down hosts see - it is the
parser the inventory goes through everywhere. That makes two things worth
proving. First, that it agrees with real PyYAML wherever PyYAML is available
to ask, including on the inventory template this repo actually ships, so the
shadowing changes nothing about what a file means. Second, that everything it
does not support fails loudly, because the damage from a mis-read inventory is
not a crash - it is a clean-looking compliance report built on the wrong VLANs.
"""

import os
import sys

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(PROJECT, 'scripts')
sys.path.insert(0, SCRIPTS)

import yaml as stub

failures = []


def check(name, condition, detail=''):
    print(f'  {"ok  " if condition else "FAIL"} {name}')
    if not condition:
        if detail:
            print(f'       {detail}')
        failures.append(name)


def real_pyyaml():
    """The installed PyYAML, if there is one, with scripts/ off the path."""
    saved_path, saved_module = list(sys.path), sys.modules.pop('yaml', None)
    try:
        sys.path = [p for p in sys.path if os.path.abspath(p) != SCRIPTS]
        import yaml as installed
        return installed
    except ImportError:
        return None
    finally:
        sys.path = saved_path
        sys.modules.pop('yaml', None)
        if saved_module is not None:
            sys.modules['yaml'] = saved_module


REFERENCE = real_pyyaml()


def agrees(name, text, expected):
    """Parse to `expected`, and to whatever PyYAML says when it is installed."""
    try:
        produced = stub.safe_load(text)
    except stub.YAMLError as error:
        check(name, False, f'raised: {error}')
        return
    check(name, produced == expected, produced)
    if REFERENCE is not None:
        reference = REFERENCE.safe_load(text)
        check(f'{name} - same as PyYAML', produced == reference,
              f'stub {produced!r} vs pyyaml {reference!r}')


def refuses(name, text):
    try:
        produced = stub.safe_load(text)
    except stub.YAMLError:
        check(name, True)
        return
    check(name, False, f'parsed as {produced!r} instead of raising')


def test_the_shapes_an_inventory_is_made_of():
    print('\nthe shapes an inventory is made of')
    agrees('a flat mapping', 'automation_host: 10.0.0.5\n',
           {'automation_host': '10.0.0.5'})
    agrees('devices nest two deep',
           'devices:\n'
           '  SWITCH01:\n'
           '    host: 10.0.0.11\n'
           '    device_type: cisco_ios\n',
           {'devices': {'SWITCH01': {'host': '10.0.0.11',
                                     'device_type': 'cisco_ios'}}})
    agrees('a sequence indented under its key',
           'services:\n'
           '  ntp_servers:\n'
           '    - 10.0.0.1\n'
           '    - 10.0.0.2\n',
           {'services': {'ntp_servers': ['10.0.0.1', '10.0.0.2']}})
    agrees('a sequence at its key\'s own indent',
           'services:\n'
           '  ntp_servers:\n'
           '  - 10.0.0.1\n'
           '  - 10.0.0.2\n',
           {'services': {'ntp_servers': ['10.0.0.1', '10.0.0.2']}})
    agrees('a mapping of name to list',
           'external_interfaces_by_device:\n'
           '  ROUTER01:\n'
           '    - GigabitEthernet0/0\n',
           {'external_interfaces_by_device': {'ROUTER01': ['GigabitEthernet0/0']}})
    agrees('empty collections', 'non_user_vlans: []\ndevices: {}\n',
           {'non_user_vlans': [], 'devices': {}})


def test_the_scalars_a_verdict_depends_on():
    print('\nthe scalars a verdict depends on')
    agrees('a VLAN id is an int, not a string', 'unused_vlan: 999\n',
           {'unused_vlan': 999})
    agrees('an unset key is None, as the .get() defaults expect',
           'unused_vlan:\n', {'unused_vlan': None})
    agrees('so is an explicit null', 'native_vlan: null\n', {'native_vlan': None})
    agrees('and a tilde', 'native_vlan: ~\n', {'native_vlan': None})
    agrees('booleans', 'enabled: true\ndisabled: false\n',
           {'enabled': True, 'disabled': False})
    agrees('a subnet keeps its prefix length as text',
           'management_subnet: 10.0.0.0/24\n',
           {'management_subnet': '10.0.0.0/24'})
    agrees('an address is text, not a number',
           'host: 10.0.0.11\n', {'host': '10.0.0.11'})
    agrees('quoted names survive quoting',
           'user_vlan_names:\n  - "USERS"\n  - \'VOICE\'\n',
           {'user_vlan_names': ['USERS', 'VOICE']})
    agrees('a glob keeps its wildcard',
           'user_vlan_names:\n  - "*user[0-9]*"\n',
           {'user_vlan_names': ['*user[0-9]*']})


def test_comments_are_the_point_of_this():
    print('\ncomments are the point of this')
    agrees('a whole-line comment',
           '# which switches exist\ndevices: {}\n', {'devices': {}})
    agrees('a trailing comment',
           'unused_vlan: 999  # parked here when a port is shut\n',
           {'unused_vlan': 999})
    agrees('a blank line between sections',
           'a: 1\n\n\nb: 2\n', {'a': 1, 'b': 2})
    agrees('a # inside quotes is not a comment',
           'vtp_domain: "LAB#1"\n', {'vtp_domain': 'LAB#1'})
    agrees('a comment against a nested key',
           'services:\n'
           '  # the only servers the audit will accept\n'
           '  ntp_servers:\n'
           '    - 10.0.0.1  # core\n',
           {'services': {'ntp_servers': ['10.0.0.1']}})


def test_json_inventories_still_load():
    print('\nJSON inventories still load')
    agrees('an inventory written as JSON',
           '{"devices": {"SW01": {"host": "10.0.0.11"}}, "non_user_vlans": [1, 10]}',
           {'devices': {'SW01': {'host': '10.0.0.11'}}, 'non_user_vlans': [1, 10]})
    agrees('pretty-printed JSON, the shape inventory.yaml.example used to have',
           '{\n  "unused_vlan": 999,\n  "native_vlan": 998\n}\n',
           {'unused_vlan': 999, 'native_vlan': 998})


def test_the_template_this_repo_ships():
    print('\nthe template this repo ships')
    path = os.path.join(PROJECT, 'inventory.yaml.example')
    check('inventory.yaml.example exists', os.path.exists(path), path)
    if not os.path.exists(path):
        return
    with open(path, encoding='utf-8') as handle:
        loaded = stub.safe_load(handle)
    check('it parses', isinstance(loaded, dict), type(loaded).__name__)
    if not isinstance(loaded, dict):
        return
    check('devices is a mapping, which load_inventory() indexes directly',
          isinstance(loaded.get('devices'), dict), loaded.get('devices'))
    check('management_subnet is present - absent, V-220575/523 FAILs every device',
          'management_subnet' in loaded, sorted(loaded))
    check('services carries the three server lists',
          set(loaded.get('services', {})) >=
          {'ntp_servers', 'syslog_servers', 'radius_servers'},
          loaded.get('services'))
    if REFERENCE is not None:
        with open(path, encoding='utf-8') as handle:
            reference = REFERENCE.safe_load(handle)
        check('and PyYAML reads the shipped template identically',
              loaded == reference,
              'differs on: %s' % sorted(
                  k for k in set(loaded) | set(reference)
                  if loaded.get(k) != reference.get(k)))


def test_what_it_will_not_guess_at():
    print('\nwhat it will not guess at')
    refuses('a tab in the indentation', 'devices:\n\tSW01: {}\n')
    refuses('a duplicate key', 'unused_vlan: 999\nunused_vlan: 998\n')
    refuses('an anchor', 'a: &base\n  x: 1\n')
    refuses('an alias', 'a:\n  x: 1\nb: *base\n')
    refuses('a block scalar', 'banner: |\n  line one\n  line two\n')
    refuses('a non-empty inline list', 'non_user_vlans: [1, 10]\n')
    refuses('a non-empty inline mapping', 'devices: {SW01: {host: 10.0.0.1}}\n')
    refuses('a list of mappings', 'devices:\n  - name: SW01\n    host: 10.0.0.1\n')
    refuses('an unterminated quote', 'vtp_domain: "LAB\n')
    refuses('a second document', 'a: 1\n---\nb: 2\n')
    refuses('a line that is neither a key nor a list item', 'devices:\n  SW01\n')


def test_the_error_says_where():
    print('\nthe error says where')
    try:
        stub.safe_load('devices:\n  SW01:\n    host: 10.0.0.1\nunused_vlan: [1, 2]\n')
        check('a refusal names the line', False, 'did not raise')
    except stub.YAMLError as error:
        check('a refusal names the line', 'line 4' in str(error), str(error))
    try:
        stub.safe_load('unused_vlan: 999\nunused_vlan: 998\n')
        check('a duplicate key names the key', False, 'did not raise')
    except stub.YAMLError as error:
        check('a duplicate key names the key', 'unused_vlan' in str(error), str(error))


if __name__ == '__main__':
    print('PyYAML %s' % (REFERENCE.__version__ if REFERENCE else
                         'not installed - parity checks skipped'))
    for test in (test_the_shapes_an_inventory_is_made_of,
                 test_the_scalars_a_verdict_depends_on,
                 test_comments_are_the_point_of_this,
                 test_json_inventories_still_load,
                 test_the_template_this_repo_ships,
                 test_what_it_will_not_guess_at,
                 test_the_error_says_where):
        test()
    print('\n' + ('ALL CHECKS PASSED' if not failures
                  else f'{len(failures)} FAILED: {", ".join(failures)}'))
    sys.exit(1 if failures else 0)
