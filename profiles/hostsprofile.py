"""Host profiles for our controller"""

#
# NOTE: This code was machine converted. An actual human would not
#       write code like this!
#

# Import the Portal object.
import geni.portal as portal
# Import the ProtoGENI library.
import geni.rspec.pg as pg
# Import the Emulab specific extensions.
import geni.rspec.emulab as emulab

# Create a portal object,
pc = portal.Context()

# Create a Request object to start building the RSpec.
request = pc.makeRequestRSpec()

# Node node-1
node_1 = request.XenVM('node-1')
node_1.disk_image = 'urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD'
iface0 = node_1.addInterface('interface-0')
iface1 = node_1.addInterface('interface-7')

# Node node-2
node_2 = request.XenVM('node-2')
node_2.disk_image = 'urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD'
iface2 = node_2.addInterface('interface-1')
iface3 = node_2.addInterface('interface-3')

# Node node-3
node_3 = request.XenVM('node-3')
node_3.disk_image = 'urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD'
iface4 = node_3.addInterface('interface-2')
iface5 = node_3.addInterface('interface-5')

# Node node-4
node_4 = request.XenVM('node-4')
node_4.disk_image = 'urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD'
iface6 = node_4.addInterface('interface-4')
iface7 = node_4.addInterface('interface-6')

# Link link-0
link_0 = request.LAN('link-0')
link_0.Site('undefined')
link_0.addInterface(iface0)
link_0.addInterface(iface2)

# Link link-1
link_1 = request.LAN('link-1')
link_1.Site('undefined')
link_1.addInterface(iface4)
link_1.addInterface(iface3)

# Link link-2
link_2 = request.LAN('link-2')
link_2.Site('undefined')
link_2.addInterface(iface6)
link_2.addInterface(iface5)

# Link link-3
link_3 = request.LAN('link-3')
link_3.Site('undefined')
link_3.addInterface(iface7)
link_3.addInterface(iface1)


# Print the generated rspec
pc.printRequestRSpec(request)
