"""CloudLab SDN firewall profile with 1 controller, 1 switch, and 4 hosts."""

import geni.portal as portal
import geni.rspec.pg as pg

pc = portal.Context()
request = pc.makeRequestRSpec()

IMAGE = "urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD"

# Controller node
controller = request.XenVM("controller")
controller.disk_image = IMAGE
controller.addService(pg.Execute(shell="sh", command="/local/repository/controller.sh"))

# Switch node
switch = request.XenVM("switch")
switch.disk_image = IMAGE
switch.addService(pg.Execute(shell="sh", command="/local/repository/switch.sh"))

# Host nodes
hosts = []
for i in range(1, 5):
    host = request.XenVM(f"host{i}")
    host.disk_image = IMAGE
    host.addService(
        pg.Execute(
            shell="sh",
            command=f"/local/repository/host.sh 10.0.0.{i}/24"
        )
    )
    hosts.append(host)

# Connect each host to the switch
for i, host in enumerate(hosts, start=1):
    host_if = host.addInterface(f"host{i}-if")
    host_if.addAddress(pg.IPv4Address(f"10.0.0.{i}", "255.255.255.0"))

    switch_if = switch.addInterface(f"switch-if{i}")

    link = request.Link(f"link-host{i}-switch")
    link.addInterface(host_if)
    link.addInterface(switch_if)

pc.printRequestRSpec(request)