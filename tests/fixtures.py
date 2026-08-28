#!/usr/bin/env python
"""Synthetic device output shared by the tests.

Not taken from any real switch. Addressing is RFC 5737 documentation space and
the hostname is invented, so this file is safe to commit where a real capture
would not be - see capture.py. Shaped like a Catalyst running IOS XE, including
a TwentyFiveGigE uplink, so the interface-prefix handling is exercised too.
"""

RUNNING_CONFIG = """Building configuration...

Current configuration : 4211 bytes
!
version 17.9
service timestamps debug datetime msec localtime show-timezone
service timestamps log datetime msec localtime show-timezone
service password-encryption
!
hostname TESTSW01
!
aaa new-model
aaa authentication login default group radius local
aaa accounting exec default start-stop group radius
!
no ip domain-lookup
ip domain name example.test
!
vtp mode transparent
!
spanning-tree mode rapid-pvst
spanning-tree portfast bpduguard default
!
vlan 10
 name MGMT
!
vlan 20
 name USERS
!
vlan 999
 name NATIVE
!
vlan 1000
 name UNUSED
!
ip dhcp snooping vlan 20
ip dhcp snooping
ip arp inspection vlan 20
!
interface GigabitEthernet1/0/1
 description user port
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast
 spanning-tree bpduguard enable
 ip verify source
!
interface GigabitEthernet1/0/2
 description disabled port
 switchport mode access
 switchport access vlan 1000
 shutdown
!
interface TwentyFiveGigE1/1/1
 description uplink to core
 switchport mode trunk
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20
 ip dhcp snooping trust
 ip arp inspection trust
!
interface Vlan10
 ip address 192.0.2.5 255.255.255.0
!
banner login ^C
You are accessing a U.S. Government (USG) Information System (IS) that is
provided for USG-authorized use only.
^C
!
line con 0
 exec-timeout 5 0
 logging synchronous
line vty 0 4
 exec-timeout 5 0
 transport input ssh
 session-limit 5
!
logging buffered 64000
logging host 192.0.2.20
logging host 192.0.2.21
logging trap informational
!
ntp authenticate
ntp server 192.0.2.30
ntp server 192.0.2.31
!
snmp-server group STIGGRP v3 priv
!
ip ssh version 2
ip ssh server algorithm mac hmac-sha2-256
ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr
!
end"""

VLAN_BRIEF = """VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active
10   MGMT                             active    Vl10
20   USERS                            active    Gi1/0/1
999  NATIVE                           active
1000 UNUSED                           active    Gi1/0/2
1002 fddi-default                     act/unsup
1003 trcrf-default                    act/unsup
1004 fddinet-default                  act/unsup
1005 trbrf-default                    act/unsup"""

SPANNING_TREE = """VLAN0010
  Spanning tree enabled protocol rstp
  Root ID    Priority    24586
             Address     0011.2233.4455
             Cost        4
             Port        1 (TwentyFiveGigE1/1/1)
             Hello Time  2 sec  Max Age 20 sec  Forward Delay 15 sec

VLAN0020
  Spanning tree enabled protocol rstp
  Root ID    Priority    24596
             Address     0011.2233.4455
             Cost        4
             Port        1 (TwentyFiveGigE1/1/1)
             Hello Time  2 sec  Max Age 20 sec  Forward Delay 15 sec"""

VTP_PASSWORD = 'The VTP password is not configured.'

SNMP_USER = """User name: stigadmin
Engine ID: 800000090300AABBCCDDEEFF
storage-type: nonvolatile        active
Authentication Protocol: SHA
Privacy Protocol: AES128
Group-name: STIGGRP"""

OUTPUTS = {
    'show running-config': RUNNING_CONFIG,
    'show vlan brief': VLAN_BRIEF,
    'show spanning-tree': SPANNING_TREE,
    'show vtp password': VTP_PASSWORD,
    'show snmp user': SNMP_USER,
}
