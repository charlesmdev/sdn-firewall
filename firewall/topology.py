from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel


def build_topology():
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch)

    # Ryu's default OpenFlow port is usually 6653.
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653
    )

    # OpenFlow 1.3 switch.
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    # Four hosts connected to the switch.
    hosts = []
    for i in range(1, 5):
        h = net.addHost(
            f'h{i}',
            ip=f'10.0.0.{i}/24',
            mac=f'00:00:00:00:00:0{i}'
        )
        net.addLink(h, s1)
        hosts.append(h)

    net.start()
    print("[*] Network started. Controller expected at 127.0.0.1:6653")

    CLI(net)

    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    build_topology()
