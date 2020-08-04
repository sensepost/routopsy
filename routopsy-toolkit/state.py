from ospf import OSPF as ospf_packet
from data import Data as user_var
from eigrp import EIGRP as eigrp_packet
from rip import RIP as rip_packet


# HSRP Configuration/State

class hsrp_config:
    def __init__(self):
        self.ipv4_forward_enabled = False
        self.default_gateway = None

    def set_default_gateway(self, gateway):
        self.default_gateway = gateway

    def set_ipv4_forward_enabled(self, enabled):
        self.ipv4_forward_enabled = enabled

class routing_table:
    def __init__(self):
        self.network_with_cidr = []
        self.gateways = []

    def set_network_with_cidr(self, network_with_cidr):
        self.network_with_cidr = network_with_cidr

    def set_gateways(self, gateways):
        self.gateways = gateways

#default gateway set before performing an HSRP attack

routing_table = routing_table()
hsrp_config = hsrp_config()
ospf_packet = ospf_packet()
user_var = user_var()
eigrp_packet = eigrp_packet()
rip_packet = rip_packet()
vulnerable_ospf_packets = []
vulnerable_eigrp_packets = []
vulnerable_rip_packets = []
vulnerable_hsrp_packets = []
vulnerable_vrrp_packets = []