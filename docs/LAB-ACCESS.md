# Reaching the multi-vendor lab (SecureCRT, SSH, Ansible)

How to get a session on the devices in the **Network Automation** GNS3 project.
The lab is built by:

```
python lab/rebuild_lab.py --topology lab/topology_multivendor.yaml
python lab/rebuild_lab.py --topology lab/topology_multivendor.yaml --verify   # health check
```

## The shape of the problem

The lab's management segment is `10.10.50.0/24`, and it exists **inside GNS3**.
Windows has no route to it, and adding one needs an elevated prompt:

```
Windows 192.168.33.1 ──VMnet1── GNS3 VM 192.168.33.130
Windows 192.168.231.1 ─VMnet8── GNS3 VM 192.168.231.130
                                     │
                                 [ Cloud1 port 1 ]
                                     │
             automation container  eth1 192.168.231.50   <- Windows CAN reach this
                                   eth0 10.10.50.10      <- and this side is on the lab
                                     │
                                 [ MgmtSw ]
                      R1 .11   R2 .17   SW1 .12   SW2 .13
```

The automation container has a foot in both networks. That makes it the jump
host, and it is why `lab/topology_multivendor.yaml` gives it two adapters.

## Option A - SecureCRT through the jump host (no admin needed)

This is the default and needs nothing changed on Windows.

**1. Create the jump-host session** (once):

| Field | Value |
|---|---|
| Protocol | SSH2 |
| Hostname | `192.168.231.50` |
| Username | `root` |
| Authentication | **PublicKey** only - uncheck Password |
| Identity file | `C:\Users\<you>\.ssh\netauto_ed25519` |

Root login on the container is key-only on purpose (`PermitRootLogin
prohibit-password`), so password auth will fail by design. Name the session
something like `lab-jump`.

**2. Create one session per device**, and point each at the jump host:

* Hostname: the device's management address (`10.10.50.11` for R1, `.17` R2,
  `.12` SW1, `.13` SW2)
* Username: `admin`
* **Session Options -> Connection -> Firewall -> Select Session...** and choose
  `lab-jump`

SecureCRT then opens the device session *through* the container. Device
credentials are the lab ones, not the container key.

## Option B - a route, for direct sessions

One elevated command on Windows, and every device is directly reachable at its
`10.10.50.x` address with no per-session firewall setting:

```
route -p add 10.10.50.0 mask 255.255.255.0 192.168.231.50
```

`-p` makes it survive a reboot. This needs the container running to be useful,
and the container needs IP forwarding on (`sysctl -w net.ipv4.ip_forward=1`),
which is not set by default.

Option A is the one to use if you do not want to think about it again.

## Devices and addresses

| Device | Management | Platform | Notes |
|---|---|---|---|
| automation container | `192.168.231.50` / `10.10.50.10` | Debian | jump host, Ansible controller, repo clone |
| R1 | `10.10.50.11` | IOSv | HSRP active, priority 110, preempt |
| R2 | `10.10.50.17` | IOSv | HSRP standby, priority 100 |
| SW1 | `10.10.50.12` | IOSvL2 | pure L2, management SVI on VLAN 99 |
| SW2 | `10.10.50.13` | IOSvL2 | pure L2, management SVI on VLAN 99 |
| PC10 | - | VPCS | `10.0.10.100`, VLAN 10, console only |
| PC20 | - | VPCS | `10.0.20.100`, VLAN 20, console only |
| JSW1 | `10.10.50.14` | vJunos | fxp0 addressed, SSH and NETCONF (830) up - see below |
| JSW2 | `.15` | vJunos | node exists and is cabled, but **stopped and unconfigured** (RAM) |
| PA1 | `.16` | PAN-OS | not built - no image |

### The Juniper switches

The image works: patched for AMD (see `lab/images.yaml`) it boots to a real
Junos CLI - `JUNOS 26.2R1.7`, model `ex9214`. `rebuild_lab.py` bootstraps
`JSW1` over its console with nobody watching: hostname, root and `admin`
passwords, SSH, NETCONF, and fxp0 at `10.10.50.14`, behind a `commit check`.
Afterwards NETCONF answers from the controller on 830 and on 22.

`JSW2` has the same config waiting, commented out in
`lab/topology_multivendor.yaml`. The only reason it is not running is memory.

Two practical constraints:

* **RAM.** 5 GB each and their RSS grows past it. Both of them plus the Cisco
  lab took the 24 GB GNS3 VM down to 178 MB free. Start **one** at a time.
* **Boot time.** ~10 minutes to a usable CLI, and it is silent for most of it.

To bring one up by hand:

```
# start JSW1 in the GNS3 UI (or via the API), wait ~10 minutes, then:
python lab/rebuild_lab.py --topology lab/topology_multivendor.yaml --only JSW1
```

`--only` skips node creation and the end-to-end pings, so it is the cheap way
to retry a slow device without re-pushing four Cisco boxes first.

### Stopping a Juniper switch without breaking it

Check the node's **On close** setting before you stop one. GNS3's default,
`power_off`, gives qemu 3 seconds and then kills it, so Junos never shuts
down. The vJunos template now uses `shutdown_signal` (see `lab/images.yaml`):
the ACPI power button makes the image halt cleanly, telling the inner Junos to
`halt -p` first. A stop then takes a minute or two instead of seconds, which is
the point.

A node created before that change keeps `power_off`. Fix it once through the
API while the node is stopped:

```
curl -X PUT http://192.168.33.130/v2/projects/<project-id>/nodes/<node-id> \
  -H 'Content-Type: application/json' \
  -d '{"properties": {"on_close": "shutdown_signal"}}'
```

What an unclean stop looks like on the next boot: minutes of fsck on the
console (`UNEXPECTED SOFT UPDATE INCONSISTENCY`, `SALVAGE? yes`), then a CLI
where every command fails with
`error: schema: action: unresolved function 'mgd_...'` and
`remote side unexpectedly closed connection`. That is disk damage, not a switch
that is still booting, and waiting does not fix it.

### Recovering a Juniper switch with a damaged disk

Each node's disk is a small linked-clone overlay on the shared base image, so
a damaged switch can be reset to factory state without touching the image:

1. Stop the node. A hard stop is fine, since it is already broken.
2. On the GNS3 VM, move the overlay aside (keep it rather than deleting it):
   `mv /opt/gns3/projects/<project-id>/project-files/qemu/<node-id>/hda_disk.qcow2{,.broken}`
3. Start the node. GNS3 creates a fresh overlay from the base image.
4. Once it has booted, rerun `--only <name>`: a factory-fresh switch is exactly
   what the bootstrap expects.

This loses the switch's configuration, which the bootstrap recreates. It does
not lose anything else, because nothing else lives on these switches.

Device login is `admin`; the password is whatever was passed as `SSH_PASSWORD`
when the lab was built. It is not stored in the repo.

## Consoles, when SSH is not the problem you have

Every node also has a telnet console on the GNS3 server, which works even when
a device has no addressing at all - it is how `rebuild_lab.py` bootstraps them:

```
telnet 192.168.33.130 <port>
```

Ports are per node and move when nodes are recreated; read them from the API:

```
curl -s http://192.168.33.130/v2/projects/<project-id>/nodes \
  | python -c "import json,sys; [print(n['name'], n['console']) for n in json.load(sys.stdin)]"
```

## Ansible

The controller is the container, which carries its own clone of this repo at
`/root/NetworkAutomation`. **That clone lags your local edits** - it is a
`git clone`, not a mount - so `git pull` there before blaming a playbook for
behaving like an older version of itself.

```
ssh -i ~/.ssh/netauto_ed25519 root@192.168.231.50
cd /root/NetworkAutomation && git pull
ansible -i ansible/inventory/hosts.yml ios_routers -m ios_facts
```
