#!/usr/bin/env python3
"""Lab 7 topology: one OpenFlow 1.3 switch and four hosts.

Run this on the Mininet VM, not the laptop:

    sudo python3 topo_lab7.py

The switch connects to the Ryu controller at 10.0.0.211:6653
(simple_switch_13 and ofctl_rest). Host addresses:

    h1  10.0.0.1/24  00:00:00:00:00:01
    h2  10.0.0.2/24  00:00:00:00:00:02
    h3  10.0.0.3/24  00:00:00:00:00:03
    h4  10.0.0.4/24  00:00:00:00:00:04

Startup writes a connectivity check to /tmp/lab7_verify.txt, then
opens the Mininet CLI.
"""

from __future__ import annotations

import time

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.topo import Topo

CONTROLLER_IP = "10.0.0.211"
CONTROLLER_PORT = 6653
SWITCH_DPID = "0000000000000001"
VERIFY_PATH = "/tmp/lab7_verify.txt"


class Lab7Topo(Topo):
    """Single switch s1 with hosts h1-h4."""

    def build(self):
        switch = self.addSwitch(
            "s1",
            dpid=SWITCH_DPID,
            protocols="OpenFlow13",
            failMode="secure",
        )
        for index in range(1, 5):
            host = self.addHost(
                f"h{index}",
                ip=f"10.0.0.{index}/24",
                mac=f"00:00:00:00:00:0{index}",
            )
            self.addLink(host, switch)


def wait_for_controller(switch, timeout: int = 20) -> None:
    """Block until OVS reports the remote controller as connected."""

    deadline = time.time() + timeout
    while time.time() < deadline:
        show = switch.cmd("ovs-vsctl show")
        if "is_connected: true" in show:
            return
        time.sleep(1)
    raise RuntimeError(
        f"s1 did not connect to {CONTROLLER_IP}:{CONTROLLER_PORT} "
        f"within {timeout} seconds."
    )


def verify(net: Mininet) -> None:
    """Record host addresses, the OpenFlow handshake, and pingall loss."""

    switch = net.get("s1")
    lines = ["Lab 7 topology check", ""]

    for host in net.hosts:
        lines.append(f"{host.name}  ip={host.IP()}  mac={host.MAC()}")

    lines.append("")
    lines.append(switch.cmd("ovs-ofctl -O OpenFlow13 show s1").rstrip())
    lines.append("")
    lines.append(switch.cmd("ovs-ofctl -O OpenFlow13 dump-flows s1").rstrip())
    lines.append("")

    loss = net.pingAll()
    lines.append(f"pingall packet loss: {loss}%")
    lines.append("")
    lines.append(switch.cmd("ovs-ofctl -O OpenFlow13 dump-flows s1").rstrip())

    report = "\n".join(lines) + "\n"
    with open(VERIFY_PATH, "w", encoding="utf-8") as handle:
        handle.write(report)
    info(report)


def main() -> None:
    setLogLevel("info")
    net = Mininet(
        topo=Lab7Topo(),
        switch=OVSKernelSwitch,
        controller=lambda name: RemoteController(
            name,
            ip=CONTROLLER_IP,
            port=CONTROLLER_PORT,
        ),
        autoSetMacs=False,
    )
    net.start()
    try:
        wait_for_controller(net.get("s1"))
        time.sleep(1)
        verify(net)
        CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    main()
