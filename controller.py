import logging

import matplotlib
import networkx as nx

# Use 'Agg' backend to safely generate plots in non-main threads (eventlet greenlets)
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from eventlet.semaphore import Semaphore
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib.packet import ether_types, ethernet, packet
from os_ken.ofproto import ofproto_v1_3
from os_ken.topology import event


class TopologyChangeDetector(app_manager.OSKenApp):
    # Specify OpenFlow 1.3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TopologyChangeDetector, self).__init__(*args, **kwargs)

        # Initialize an empty undirected graph to store the topology
        self.net = nx.Graph()

        # Dictionary to keep track of MAC-to-port mappings for L2 switching
        self.mac_to_port = {}

        # Configure logging
        self.logger.setLevel(logging.INFO)

        # Semaphore lock to prevent concurrent drawing collisions
        self.draw_lock = Semaphore()

        self.logger.info("Topology Change Detector & L2 Switch Initialized.")

    # =============================================
    # LAYER 2 SWITCHING LOGIC (Enables PING)
    # =============================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install a Table-Miss flow entry when a switch connects."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Default rule: send all unmatched packets to the controller
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Helper to add an OpenFlow rule to a switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match, instructions=inst
            )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Handle incoming packets, learn MACs, and route traffic."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP packets (used for topology discovery, not normal traffic)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn the MAC address of the source host to avoid flooding next time
        self.mac_to_port[dpid][src] = in_port

        # Determine the output port for the destination MAC
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD  # Flood if destination is unknown

        actions = [parser.OFPActionOutput(out_port)]

        # If we know the output port, install a flow to skip the controller next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        # Send the packet out to the network
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    # =============================================
    # TOPOLOGY DISCOVERY LOGIC (Builds the Graph)
    # =============================================
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch_id = f"s{ev.switch.dp.id}"
        self.logger.info(f"[EVENT] Switch Entered: {switch_id}")
        self.net.add_node(switch_id, type="switch")
        self.update_topology_graph()

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        switch_id = f"s{ev.switch.dp.id}"
        self.logger.info(f"[EVENT] Switch Left: {switch_id}")
        if self.net.has_node(switch_id):
            self.net.remove_node(switch_id)
        self.update_topology_graph()

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        src = f"s{ev.link.src.dpid}"
        dst = f"s{ev.link.dst.dpid}"
        self.logger.info(f"[EVENT] Link Added: {src} <---> {dst}")
        self.net.add_edge(src, dst)
        self.update_topology_graph()

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        src = f"s{ev.link.src.dpid}"
        dst = f"s{ev.link.dst.dpid}"
        self.logger.info(f"[EVENT] Link Deleted: {src} </-> {dst}")
        if self.net.has_edge(src, dst):
            self.net.remove_edge(src, dst)
        self.update_topology_graph()

    @set_ev_cls(event.EventHostAdd)
    def host_add_handler(self, ev):
        host_mac = ev.host.mac
        switch_id = f"s{ev.host.port.dpid}"
        self.logger.info(
            f"[EVENT] Host Discovered: {host_mac} connected to {switch_id}"
        )

        self.net.add_node(host_mac, type="host")
        self.net.add_edge(host_mac, switch_id)
        self.update_topology_graph()

    # =============================================
    # VISUALIZATION LOGIC
    # =============================================
    def update_topology_graph(self):
        with self.draw_lock:
            try:
                plt.clf()
                plt.figure(figsize=(10, 8))
                pos = nx.spring_layout(self.net, seed=42)

                switches = [
                    n
                    for n, d in self.net.nodes(data=True)
                    if d.get("type", "switch") == "switch"
                ]
                hosts = [
                    n for n, d in self.net.nodes(data=True) if d.get("type") == "host"
                ]

                if switches:
                    nx.draw_networkx_nodes(
                        self.net,
                        pos,
                        nodelist=switches,
                        node_color="#4CA1AF",
                        node_size=2000,
                        node_shape="s",
                    )

                if hosts:
                    nx.draw_networkx_nodes(
                        self.net,
                        pos,
                        nodelist=hosts,
                        node_color="#2ECC71",
                        node_size=1200,
                        node_shape="o",
                    )

                nx.draw_networkx_edges(self.net, pos, edge_color="#2C3E50", width=2.5)

                labels = {}
                for n in self.net.nodes():
                    if n in hosts and isinstance(n, str) and ":" in n:
                        labels[n] = ".." + str(n)[-8:]
                    else:
                        labels[n] = str(n)

                nx.draw_networkx_labels(
                    self.net,
                    pos,
                    labels=labels,
                    font_size=10,
                    font_weight="bold",
                    font_color="black",
                )

                plt.title("Dynamic Network Topology (Switches & Hosts)", fontsize=16)
                plt.axis("off")

                filename = "network_topology.png"
                plt.savefig(filename, bbox_inches="tight")
                plt.close()

                self.logger.info(f"[*] Map Updated. Saved to {filename}")
            except Exception as e:
                self.logger.error(f"[!] Failed to update graph: {e}")
