# gtpd
A daemon connecting Linux network namespaces over GTPU tunnels.

The anticipated use case is manual or scripted testing of GTPU infrastructure.
In order to conduct testing, one creates and configures a Linux network namespace.
One can use standard tools inside the namespace, e.g. `ping` and `iperf`,
to generate GTPU traffic with interesting propeties.

Distinguishing features:
  * Supports multiple simultaneous sessions with overlapping endpoint IPs.
 
  * A common testing scenario with both client
    and server hosted on the same machine is fully supported.
    
    E.g. **iperf client** → **GTPU tunnel** ⋯ → **iperf server**.
    
  * High performance. 🚀
  
    Multi-threaded, exchanging multiple datagrams
    in a batch, taking advantage of zero-copy XDP and leveraging BPF.

## Implementation overview

The daemon bridges UDP port 2152 with *TAP* devices in secondary network namespaces.

Note: a TAP device is a virtual network interface allowing to
consume egress and inject ingress traffic programmatically.
We emulate TAP devices with virtual Ethernet pairs for better performance.

```
+---------------------------+  +-----------------------+
| Primary Network Namespace |  |          Ns1          |
|                           |  |  gtpd_tap ==== eth0   |
| UDP *:2152                |  +-----------------------+
|                           |  
| UDP ::0:2152              |  +-----------------------+
|                           |  |          Ns2          |
+---------------------------+  |  gtpd_tap ==== eth0   |
                               +-----------------------+
```
The daemon receives commands via a UNIX domain socket connection.
The listening socket is bound at `/run/gtpd`.

A secondary network namespace is attached using `gtpd_ctl add` command, e.g:
```
gtpd_ctl add local 10.99.100.91 remote 10.99.100.90 dev gtpd_tap
```
The tool opens `gtpd_tap` interface and sends the corresponding file descriptor
alongside the add tunnel command to the daemon.
The tool must run in the network namespace `gtpd_tap` belongs to.

One can have both `gtpd_tap` and `eth0` in the secondary network namespace.
A more common config with a veth pair spanning namespaces is also working.

Note: veth pair needs some twidling with as `gtpd` doesn't implement ARP.
See `test_env.sh` for details. A short human-readable summary:
  * turn ARP off on both ends;
  * set the MAC address to `00:00:00:00:00:01`;
  * disable RX checksum offloading.

## Building

Project uses CMake for building.  Please ensure that `libsystemd-dev`
is installed.  Follow the following steps to build Debian packages.
It is assumed that the working directory is the project's source root.

```
mkdir build
cd build
cmake ..
make package
```

The package provides `gtpd` daemon, `systemd` unit files and `gtpd_ctl` utility.

## Usage
### Add a tunnel
```sh
$ gtpd_ctl add local 10.99.100.91 local-teid 19909 remote 10.99.100.90 remote-teid 19909 dev eth0
1
```

### List tunnels
```sh
$ gtpd_ctl ls
# id         local  local-teid        remote  remote-teid  type  halt  encap-ok  encap-drop-rx  encap-drop-tx  decap-ok  decap-drop-rx  decap-drop-tx  decap-bad  decap-trunc
   1  10.99.100.91       19909  10.99.100.90        19909    ip     0         0              0              0         0              0              0          0            0
```
### Modify a tunnel
```sh
$ gtpd_ctl mod 1 set local-teid 1234
```
One can optionally include `set local`, `set remote` and `set remote-teid` as well.

### Remove a tunnel
```sh
$ gtpd_ctl del 1
```
