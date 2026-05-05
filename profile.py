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
    host = request.XenVM("host{}".format(i))
    host.disk_image = IMAGE
    host.addService(
        pg.Execute(
            shell="sh",
            command="/local/repository/host.sh 10.0.0.{}/24".format(i)
        )
    )
    hosts.append(host)

# Connect each host to the switch
for i, host in enumerate(hosts, start=1):
    host_if = host.addInterface("host{}-if".format(i))
    host_if.addAddress(pg.IPv4Address("10.0.0.{}".format(i), "255.255.255.0"))

    switch_if = switch.addInterface("switch-if{}".format(i))

    link = request.Link("link-host{}-switch".format(i))
    link.addInterface(host_if)
    link.addInterface(switch_if)

pc.printRequestRSpec(request)