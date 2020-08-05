from data import Data as user_var

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
user_var = user_var()
vulnerable_ospf_packets = []
vulnerable_eigrp_packets = []
vulnerable_rip_packets = []
vulnerable_hsrp_packets = []
vulnerable_vrrp_packets = []