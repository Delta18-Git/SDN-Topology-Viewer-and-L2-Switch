from mininet.link import TCLink
from mininet.topo import Topo


class SingleSwitchTopo(Topo):
    """Simple single switch topology with hosts"""

    def build(self):
        s1 = self.addSwitch("s1")
        for h in range(1, 3):
            self.addHost(f"h{h}")
            self.addLink(s1, f"h{h}", cls=TCLink, bw=40, delay="15ms")


class HierarchicalTopo(Topo):
    """
    Hierarchical/tree topology

    Topology:
              h1   h2
               \\   /
                s1
               /  \\
             s2    s3
            /       \\
          h3        h4
    """

    def build(self):
        h1 = self.addHost("h1", mac="00:00:00:00:00:01", ip="10.0.0.1/24")
        h2 = self.addHost("h2", mac="00:00:00:00:00:02", ip="10.0.0.2/24")
        h3 = self.addHost("h3", mac="00:00:00:00:00:03", ip="10.0.0.3/24")
        h4 = self.addHost("h4", mac="00:00:00:00:00:04", ip="10.0.0.4/24")

        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(s1, s2, bw=100, delay="1ms")
        self.addLink(s1, s3, bw=100, delay="1ms")
        self.addLink(s2, h3, bw=100, delay="1ms")
        self.addLink(s3, h4, bw=100, delay="1ms")


class TriangleTopo(Topo):
    """
    Triangle topology for topology change detection testing

    Topology:
        h1 --- s1 --- s2 --- h2
                \\   /
                 s3
    """

    def build(self):
        h1 = self.addHost("h1", mac="00:00:00:00:00:01", ip="10.0.0.1/24")
        h2 = self.addHost("h2", mac="00:00:00:00:00:02", ip="10.0.0.2/24")

        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")

        self.addLink(h1, s1)
        self.addLink(h2, s2)

        self.addLink(s1, s2, bw=100, delay="1ms")
        self.addLink(s1, s3, bw=100, delay="1ms")
        self.addLink(s2, s3, bw=100, delay="1ms")


topos = {
    "single": (lambda: SingleSwitchTopo()),
    "triangle": (lambda: TriangleTopo()),
    "hierarchical": (lambda: HierarchicalTopo()),
}
