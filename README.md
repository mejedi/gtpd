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

A secondary network namespace is attached using `gtpd_ctl add` command.
The tool must run in the network namespace being configured.  The tool
opens `gtpd_tap` interface and sends the corresponding file descriptor
alongside the add tunnel command to the daemon.

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
