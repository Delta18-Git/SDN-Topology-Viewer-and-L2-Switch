import logging
import time

import matplotlib
import networkx as nx

# Use 'Agg' backend to safely generate plots in non-main threads
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from eventlet.semaphore import Semaphore
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib.packet import arp, ether_types, ethernet, packet
from os_ken.ofproto import ofproto_v1_3
from os_ken.topology import event
from os_ken.topology.api import get_host, get_link, get_switch


class TopologyChangeDetector(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TopologyChangeDetector, self).__init__(*args, **kwargs)

        self.net = nx.Graph()
        self.mac_to_port = {}

        # Dictionary to track recent ARP broadcasts to prevent Broadcast Storms
        self.arp_history = {}

        self.logger.setLevel(logging.INFO)
        self.draw_lock = Semaphore()

        self.logger.info(
            "Topology API Detector & Storm-Resistant L2 Switch Initialized."
        )

    # =============================================
    # LAYER 2 SWITCHING LOGIC (With Storm Mitigation)
    # =============================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
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
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP and IPv6 Multicast (Keeps topology clean)
        if eth.ethertype in [ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6]:
            return

        # --- BROADCAST STORM MITIGATION (Loop Prevention) ---
        if eth.dst == "ff:ff:ff:ff:ff:ff" and eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkts = pkt.get_protocols(arp.arp)
            if arp_pkts:
                arp_pkt = arp_pkts[0]
                # Create a unique signature for this specific ARP request on this specific switch
                sig = (datapath.id, arp_pkt.src_mac, arp_pkt.src_ip, arp_pkt.dst_ip)
                current_time = time.time()

                # If this switch has already flooded this exact ARP in the last 5 seconds, drop it!
                if sig in self.arp_history and (
                    current_time - self.arp_history[sig] < 5
                ):
                    return
                self.arp_history[sig] = current_time
        # ----------------------------------------------------

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

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
    # TOPOLOGY DISCOVERY TRIGGERS
    # =============================================
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        self.logger.info(f"[EVENT] Switch Entered: s{ev.switch.dp.id}")
        self.update_topology_graph()

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        self.logger.info(f"[EVENT] Switch Left: s{ev.switch.dp.id}")
        self.update_topology_graph()

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        self.logger.info(
            f"[EVENT] Link Added: s{ev.link.src.dpid} <---> s{ev.link.dst.dpid}"
        )
        self.update_topology_graph()

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        self.logger.info(
            f"[EVENT] Link Deleted: s{ev.link.src.dpid} </-> s{ev.link.dst.dpid}"
        )
        self.update_topology_graph()

    @set_ev_cls(event.EventHostAdd)
    def host_add_handler(self, ev):
        self.logger.info(f"[EVENT] Host Detected: {ev.host.mac}")
        self.update_topology_graph()

    # =============================================
    # API FETCHING & VISUALIZATION LOGIC
    # =============================================
    def update_topology_graph(self):
        with self.draw_lock:
            try:
                self.net.clear()

                switches = get_switch(self)
                links = get_link(self)
                hosts = get_host(self)

                switch_interconnect_ports = set()

                for s in switches:
                    self.net.add_node(f"s{s.dp.id}", type="switch")

                for link in links:
                    src_id = f"s{link.src.dpid}"
                    dst_id = f"s{link.dst.dpid}"
                    self.net.add_edge(src_id, dst_id)

                    switch_interconnect_ports.add((link.src.dpid, link.src.port_no))
                    switch_interconnect_ports.add((link.dst.dpid, link.dst.port_no))

                for h in hosts:
                    if (h.port.dpid, h.port.port_no) in switch_interconnect_ports:
                        continue

                    mac = h.mac
                    switch_id = f"s{h.port.dpid}"
                    self.net.add_node(mac, type="host")
                    self.net.add_edge(mac, switch_id)

                self.render_graph()

            except Exception as e:
                self.logger.error(f"[!] Failed to update graph: {e}")

    def render_graph(self):
        plt.clf()
        plt.figure(figsize=(10, 8))
        pos = nx.spring_layout(self.net, seed=42)

        switches = [
            n
            for n, d in self.net.nodes(data=True)
            if d.get("type", "switch") == "switch"
        ]
        hosts = [n for n, d in self.net.nodes(data=True) if d.get("type") == "host"]

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

        plt.title("Dynamic Network Topology (Storm Resistant)", fontsize=16)
        plt.axis("off")

        filename = "network_topology.png"
        plt.savefig(filename, bbox_inches="tight")
        plt.close()
