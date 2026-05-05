"""CloudLab controller profile with Ubuntu 22 image."""

import geni.portal as portal
import geni.rspec.pg as pg
import geni.rspec.emulab as emulab

pc = portal.Context()
request = pc.makeRequestRSpec()

node_controller = request.XenVM('controller')
node_controller.disk_image = 'urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD'

# Install controller dependencies when the node boots.
node_controller.addService(pg.Execute(shell="sh", command="/local/repository/controller.sh"))

pc.printRequestRSpec(request)
