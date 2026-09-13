#!/usr/bin/env python3
"""Prove HSRP failover on the multi-vendor lab: kill R1, watch R2 take over.

Run from anywhere that reaches the GNS3 server:

    SSH_USERNAME=admin SSH_PASSWORD=... python lab/test_hsrp_failover.py

WHY THIS EXISTS. rebuild_lab.py --verify proves the lab is wired and
reachable, which is a statement about the happy path. The reason the topology
has two routers at all is the unhappy path, and nothing tested that: a pair
configured with identical priorities, or with preempt missing, passes every
reachability check and still fails the moment a router dies. This powers R1
off for real and asserts three things in order:

    1. R2 goes Active for both VLAN groups
    2. a host keeps routing while R1 is gone (the point of the whole design)
    3. R1 preempts back when it returns, so the pair does not stay inverted

It leaves the lab as it found it - R1 running and active - or fails loudly
saying what state it left behind.
"""

import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rebuild_lab import (Console, Gns3, RebuildError, get_device_credentials,
                         ios_reach_privileged_exec, load_topology, ok, step)

TOPOLOGY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'topology_multivendor.yaml')
# How long to allow for a state change. HSRP's default hold time is 10s, so
# 45s is generous without being an excuse for a pair that is actually broken.
CONVERGE_TIMEOUT = 45
# IOSv takes minutes to boot; preempt cannot happen before the image is up.
BOOT_TIMEOUT = 420


def standby_state(console, username, password, group):
    """Return the HSRP state for one group, as the device reports it."""
    ios_reach_privileged_exec(console, username, password)
    console.send('terminal length 0')
    console.read(1.5)
    out = console.run('show standby brief', quiet_seconds=5)
    for line in out.splitlines():
        fields = line.split()
        # "Gi0/2.10  10  110 P Active local 10.0.10.3 10.0.10.1"
        if len(fields) >= 5 and fields[1] == str(group):
            return next((f for f in fields
                         if f in ('Active', 'Standby', 'Init', 'Listen', 'Speak')), '?')
    return '?'


def wait_for_state(console, username, password, group, wanted, timeout, label):
    deadline = time.time() + timeout
    seen = '?'
    while time.time() < deadline:
        seen = standby_state(console, username, password, group)
        if seen == wanted:
            ok(f'{label}: group {group} is {wanted}')
            return
        time.sleep(5)
    raise RebuildError(f'{label}: group {group} never reached {wanted} '
                       f'within {timeout}s (last seen: {seen})')


def vpcs_ping(console, target, attempts=3):
    console.send('')
    console.expect(r'>\s*$', timeout=20, poke=True)
    console.run(f'ping {target} -c 1', quiet_seconds=5)   # prime ARP
    out = console.run(f'ping {target} -c {attempts}', quiet_seconds=10)
    return out.count('bytes from')


def main():
    topo = load_topology(TOPOLOGY)
    api = Gns3(topo['gns3']['server'])
    host = topo['gns3']['server'].split('//', 1)[-1].split(':')[0].split('/')[0]
    username, password = get_device_credentials()

    project = next(p for p in api.get('/projects')
                   if p['name'] == topo['gns3']['project'])
    pid = project['project_id']
    nodes = {n['name']: n for n in api.get(f'/projects/{pid}/nodes')}

    r1, r2, pc10 = nodes['R1'], nodes['R2'], nodes['PC10']

    step('baseline: R1 active, R2 standby')
    c2 = Console(host, r2['console'])
    try:
        for group in (10, 20):
            wait_for_state(c2, username, password, group, 'Standby',
                           CONVERGE_TIMEOUT, 'R2')

        step('traffic works before the failure')
        c10 = Console(host, pc10['console'])
        try:
            got = vpcs_ping(c10, '10.0.20.100')
            if got == 0:
                raise RebuildError('PC10 cannot reach PC20 before the test even starts')
            ok(f'PC10 -> PC20: {got}/3 replies with R1 active')
        finally:
            c10.close()

        step('powering R1 OFF')
        api.post(f'/projects/{pid}/nodes/{r1["node_id"]}/stop')
        ok('R1 stopped')

        step('R2 should take over')
        for group in (10, 20):
            wait_for_state(c2, username, password, group, 'Active',
                           CONVERGE_TIMEOUT, 'R2')

        step('traffic survives the failure - this is the whole point')
        c10 = Console(host, pc10['console'])
        try:
            got = vpcs_ping(c10, '10.0.20.100')
            if got == 0:
                raise RebuildError(
                    'PC10 lost all connectivity with R1 down - HSRP did not '
                    'actually carry the traffic. R1 is still powered OFF.')
            ok(f'PC10 -> PC20: {got}/3 replies with R1 DOWN')
        finally:
            c10.close()
    finally:
        c2.close()

    step('powering R1 back on (IOSv boot takes minutes)')
    api.post(f'/projects/{pid}/nodes/{r1["node_id"]}/start')
    c1 = Console(host, r1['console'])
    try:
        ios_reach_privileged_exec(c1, username, password)
        ok('R1 booted and responsive')

        step('R1 should preempt back to Active')
        for group in (10, 20):
            wait_for_state(c1, username, password, group, 'Active',
                           BOOT_TIMEOUT, 'R1')
    finally:
        c1.close()

    c2 = Console(host, r2['console'])
    try:
        for group in (10, 20):
            wait_for_state(c2, username, password, group, 'Standby',
                           CONVERGE_TIMEOUT, 'R2')
    finally:
        c2.close()

    print('\nHSRP failover proven: R2 carried traffic while R1 was down, '
          'and R1 preempted back. Lab left as found.')


if __name__ == '__main__':
    try:
        main()
    except RebuildError as error:
        print(f'\nFAILED: {error}', file=sys.stderr)
        sys.exit(1)
