# Design decisions

Why this repo is structured the way it is. The [README](README.md) covers what each script does; this covers why.

## Core principles

**Isolated high-impact changes.** The vty management ACL and the AAA/RADIUS cutover each live in their own script rather than the bulk hardening pass, so they can be run, reviewed, and rolled back independently.

**No credentials on disk or in argv.** Username and password are prompted at runtime via `getpass`. Device-level secrets (VTP, SNMPv3, RADIUS key, enable secret) load from a gitignored `secrets.yaml` — never CLI flags, where they'd land in shell history.

**No hardcoded device data.** Every IP, VLAN ID, and server address lives in `inventory.yaml`. The scripts carry STIG logic only.

**Live-tested, not just written.** Nearly every commit reflects a real push against lab hardware. Behavior that only works in theory is labeled as such.

**Coded against the literal STIG text.** Every rule check maps to the benchmark's Check Text, every fix to its Fix Text. Rules needing external infrastructure or topology judgment report NOT AUTOMATED rather than guessing — a false pass on a compliance tool is worse than no answer.

## Run order

`l2_stig_harden_global.py` runs **first**. It establishes DHCP snooping and puts ports into access mode, which the other `l2_stig_harden_*.py` scripts depend on.

`l2_stig_harden_aaa.py` runs **last**. The password policy commands (V-220590-594) need `aaa new-model` already active, so they can't be folded into the bulk pass. The enable secret is pushed and confirmed working before any AAA command is sent, since the rest of the script depends on it.

`netauto.py`'s `connect()` escalates to privileged EXEC automatically using `secrets.yaml`'s `enable_secret` if one is set — a no-op if the session is already privileged. This became necessary once `aaa new-model` governs login on a device.

## Why specific scripts are split out

### `l2_stig_harden_acl.py` — vty management ACL (V-220575)
An `access-class` that excludes the automation host's own source IP blocks every future SSH connection from it, so this runs as its own script rather than inside the bulk pass. The ACL is created first, separate from applying it — an `ip access-list` has no effect until something references it — and connectivity is confirmed after it's applied, reverting automatically if that check fails.

The ACL's trailing deny carries `log-input` (V-220581, partial). It covers rejected vty access attempts only, not general traffic, and only reaches `show logging` locally, since `logging trap critical` sits above the informational severity ACL logging uses.

### `l2_stig_harden_ipsg.py` — IP Source Guard (V-220634)
IPSG only trusts the DHCP snooping binding table, so a statically-addressed host with no DHCP lease gets its traffic dropped. Kept isolated so it can be pushed or pulled independently while that gap is unresolved.

### `l2_stig_harden_dai.py` — Dynamic ARP Inspection (V-220635)
Split out for the same reason as IPSG: DAI also only trusts the DHCP snooping binding table, so a statically-addressed host can have its ARP traffic dropped once this is pushed.

The tracked fix for both is to diff `show ip device tracking all` against `show ip dhcp snooping binding` and build entries dynamically — currently blocked on IP Device Tracking not activating on this lab's `vios_l2` image.

### `ios_router_stig_harden_urpf.py` — Unicast RPF (V-216989)
uRPF is applied only to external-facing interfaces, using the interface classification in `inventory.yaml` — applying it to internal interfaces in a lab with asymmetric paths drops legitimate traffic.

It is pushed with `allow-default`. Strict-mode uRPF validates a packet's source against the routing table and discards anything with no matching route; without `allow-default`, sources reachable only via the default route fail that check and every packet from them is dropped. On a lab router whose return path to the automation host is the default route, that includes the management traffic itself.

Unlike an `access-class`, uRPF filters **per packet** rather than at connection admission, so an already-established session is not exempt from it. That makes it categorically different from the ACL and AAA scripts: their pattern of applying a change and then checking connectivity does not apply here, because a bad push drops the packets carrying the correction. This one is verified against `inventory.yaml`'s classification before the push, not after.

### Trunk ports and DHCP snooping
`l2_stig_harden_global.py` sets both `ip dhcp snooping trust` and `ip arp inspection trust` on trunk ports. DHCP snooping bindings are learned per-switch only, so trunk and uplink ports carrying transit traffic from other switches need both trusted — otherwise DAI drops that traffic against this switch's own incomplete binding table.

## Lab hardware limitations

A handful of STIG-required commands are confirmed to not exist or function on this project's `vios_l2` lab image:

- UUFB (unknown unicast flood blocking)
- Storm control
- `mls qos`
- `security passwords min-length`
- `file privilege 15`
- 802.1x authenticator role
- Classic `radius-server host` syntax
- SISF `device-tracking policy`

The scripts still push these unconditionally, since they're correct for real Cisco hardware. `l2_device_tracking.py` in particular is IOS-XE only and untested against real hardware so far.

SNMPv3 auth/priv (V-220604/605) is config-only — there's no NMS in this lab to actually poll it.
