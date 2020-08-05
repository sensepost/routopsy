from scapy.contrib.eigrp import *
from scapy.contrib.ripng import *
from scapy.all import *
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_LLS_Hdr, OSPF_DBDesc, OSPF_LSReq, OSPF_LSA_Hdr, \
    OSPF_LSReq_Item, OSPF_LSUpd, OSPF_Router_LSA, OSPF_Link, OSPF_LSAck

load_contrib('ospf')

import protocol_parser
from state import user_var
from state import vulnerable_eigrp_packets
from state import vulnerable_hsrp_packets
from state import vulnerable_ospf_packets
from state import vulnerable_rip_packets
from state import vulnerable_vrrp_packets
from utility import protocols

from protocols import hsrp
from protocols.hsrp_packet import HSRP_PACKET
from protocols import vrrp
from protocols.vrrp_packet import VRRP_PACKET
from protocols import ospf
from protocols.ospf_packet import OSPF_PACKET
from protocols import eigrp
from protocols.eigrp_packet import EIGRP_PACKET
from protocols import rip
from protocols.rip_packet import RIP_PACKET

import colorama
from colorama import Fore, Back, Style
colorama.init(autoreset=True)

# FIXME not the best check for uniques, see if we can improve this. for now we will just look at source is              
def check_if_unique(packet, v_packets):
    exists = False

    for v_packet in v_packets:
        if packet.source_ip == v_packet.source_ip:
            exists = True

    return exists

def parent_start(packet):

    def detect_vulnerable_network_protocols(packet):
        if packet.haslayer('OSPF Hello') and 'ospf' in user_var.protocol:
            if ospf.detect_if_vulnerable(packet):
                vulnerable_ospf_packet = OSPF_PACKET()
                vulnerable_ospf_packet.set_data(*ospf.get_packet_data(packet),True)

                if not check_if_unique(vulnerable_ospf_packet, vulnerable_ospf_packets):
                    vulnerable_ospf_packets.append(vulnerable_ospf_packet)

        if packet.haslayer('EIGRP') and 'eigrp' in user_var.protocol:
            if eigrp.detect_if_vulnerable(packet):
                vulnerable_eigrp_packet = EIGRP_PACKET()
                vulnerable_eigrp_packet.set_data(*eigrp.get_packet_data(packet), True)

                if not check_if_unique(vulnerable_eigrp_packet, vulnerable_eigrp_packets):
                    vulnerable_eigrp_packets.append(vulnerable_eigrp_packet)

        if packet.haslayer('RIP header') and 'rip' in user_var.protocol:
            if rip.detect_if_vulnerable(packet):
                vulnerable_rip_packet = RIP_PACKET()
                vulnerable_rip_packet.set_data(*rip.get_packet_data(packet),True)

                if not check_if_unique(vulnerable_rip_packet, vulnerable_rip_packets):
                    vulnerable_rip_packets.append(vulnerable_rip_packet)

        if packet.haslayer('VRRP') and 'vrrp' in user_var.protocol:
            if vrrp.detect_if_vulnerable(packet):
                vulnerable_vrrp_packet = VRRP_PACKET()
                vulnerable_vrrp_packet.set_data(*vrrp.get_packet_data(packet),True)

                if not check_if_unique(vulnerable_vrrp_packet, vulnerable_vrrp_packets):
                    vulnerable_vrrp_packets.append(vulnerable_vrrp_packet)

        if packet.haslayer('HSRP') and 'hsrp' in user_var.protocol:
            if hsrp.detect_if_vulnerable(packet):
                vulnerable_hsrp_packet = HSRP_PACKET()
                vulnerable_hsrp_packet.set_data(*hsrp.get_packet_data(packet),True)

                if not check_if_unique(vulnerable_hsrp_packet, vulnerable_hsrp_packets):
                    vulnerable_hsrp_packets.append(vulnerable_hsrp_packet)

    detect_vulnerable_network_protocols(packet)

def start_scan():

    vulnerable = False

    sniff(iface=user_var.interface, prn=parent_start, store=0, count=user_var.count)

    for v_packet in vulnerable_eigrp_packets:
        vulnerable = True
        print(Fore.CYAN + Style.BRIGHT + '[+]Detected a vulnerable EIGRP configuration for {}'.format(v_packet.source_ip))

    for v_packet in vulnerable_ospf_packets:
        vulnerable = True
        print(Fore.CYAN + Style.BRIGHT + '[+]Detected a vulnerable OSPF configuration for {}'.format(v_packet.source_ip))

    for v_packet in vulnerable_rip_packets:
        vulnerable = True
        print(Fore.CYAN + Style.BRIGHT + '[+]Detected a vulnerable RIP configuration for {}'.format(v_packet.source_ip))

    for v_packet in vulnerable_vrrp_packets:
        vulnerable = True
        print(Fore.CYAN + Style.BRIGHT + '[+]Detected a vulnerable VRRP configuration for {}'.format(v_packet.source_ip))
    
    for v_packet in vulnerable_hsrp_packets:
        vulnerable = True
        print(Fore.CYAN + Style.BRIGHT + '[+]Detected a vulnerable HSRP configuration for {}'.format(v_packet.source_ip))

    return vulnerable