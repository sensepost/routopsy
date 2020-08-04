import netifaces
import iptc
from pyroute2 import IPRoute
import ipaddress
import re
import socket
import netaddr
from state import user_var

#This will keep a dictionary for all protocols and their equivalent filter in scapy.
#protocols = {'ospf':89, 'eigrp':88, 'vrrp':112}
protocols = ['ospf','eigrp','rip','vrrp','hsrp']

# too lazy to write up the regex, whoever wrote this (https://www.regextester.com/99476), thank you
ip_cidr_regex = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$'
ip_regex = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))$'


def get_ip_address_from_interface(interface_name):
    return netifaces.ifaddresses(interface_name)[netifaces.AF_INET][0]['addr']

def get_ip_netmask_from_interface(interface_name):
    return netifaces.ifaddresses(interface_name)[netifaces.AF_INET][0]['netmask']

def netmask_to_cidr(netmask):
    return netaddr.IPAddress(netmask).netmask_bits()

# def get_default_gateway():
#     #return netifaces.gateways()['default'][netifaces.AF_INET][0]
#     # FIXME running routopsy breaks how we get default gateway
#     return "192.168.76.2"


def get_default_gateway():

    defaultGateway = ''
    ip = IPRoute()
    IPv4RoutesInMainRoutingTable = ip.get_routes(family=socket.AF_INET, table=254)

    for route in IPv4RoutesInMainRoutingTable:

        if route['dst_len'] == 0 and route.get_attr('RTA_DST') is None:
            # print('gateway {}'.format(route.get_attr('RTA_GATEWAY')))
            defaultGateway = route.get_attr('RTA_GATEWAY')

    return defaultGateway

def get_data_from_layer_two_and_three(packet):
    sourceMac = packet['Ethernet'].src
    sourceIP = packet['IP'].src
    destinationMac = packet['Ethernet'].dst
    destinationIP = packet['IP'].dst

    return sourceMac, sourceIP, destinationMac, destinationIP

def iptablesSNAT(action, user_var):
    table = iptc.Table(iptc.Table.NAT)
    chain = iptc.Chain(table, "POSTROUTING")
    rule = iptc.Rule()
    rule.out_interface = user_var.interface
    rule.create_target("MASQUERADE")

    if action == 'insert':
        chain.insert_rule(rule)
    else:
        chain.delete_rule(rule)


def iptablesDNAT(action, user_var):
    table = iptc.Table(iptc.Table.NAT)
    chain = iptc.Chain(table, "PREROUTING")
    rule = iptc.Rule()
    match = iptc.Match(rule, "tcp")
    match = iptc.Match(rule, "iprange")

    # FIXME

    for cidr in user_var.redirectaddresses:

        redirectNetworks = ipaddress.ip_network(cidr)
        match.dst_range = '{}-{}'.format(redirectNetworks.network_address, redirectNetworks.broadcast_address)

        rule.add_match(match)
        t = rule.create_target("DNAT")
        t.to_destination = get_ip_address_from_interface(user_var.interface)

        if action == 'insert':
            chain.insert_rule(rule)
        else:
            chain.delete_rule(rule)

def iptablesFILTER(action, user_var):
    table = iptc.Table(iptc.Table.FILTER)
    chain = iptc.Chain(table, "DOCKER-USER")
    rule = iptc.Rule()
    rule.out_interface = user_var.interface
    rule.create_target("ACCEPT")
    chain.insert_rule(rule)
    chain.delete_rule(rule)

    if action == 'insert':
        chain.insert_rule(rule)
    else:
        chain.delete_rule(rule)


def deleteRoutes(cidr):

    for x in cidr:
        my_ip = ipaddress.ip_interface(x)
        ip_and_cidr = my_ip.with_prefixlen.split('/')
        ip = IPRoute()
        ip.route("delete", dst=ip_and_cidr[0], mask=int(ip_and_cidr[1]))


def getMainTableIPV4Routes():

    ip = IPRoute()
    gateway = []
    netwithcidr = []
    ipv4MainTableRoutes = ip.get_routes(family=socket.AF_INET, table=254)

    for route in ipv4MainTableRoutes:
        gateway.append(route.get_attr('RTA_GATEWAY'))
        netwithcidr.append(str(route.get_attr('RTA_DST')) + '/' + str(route['dst_len']))

    return netwithcidr, gateway


def editRoutes(cidr_network, gateway, action):

    ip = IPRoute()
    count = 0
    for x in cidr_network:

        try:
            my_ip = ipaddress.ip_interface(x)
            ip_and_cidr = my_ip.with_prefixlen.split('/')

            if gateway[count] is None:
                if action == 'add':
                    # print("adding None network {} mask {}".format(ip_and_cidr[0], ip_and_cidr[1]))
                    ip.route("add", dst=ip_and_cidr[0], mask=int(ip_and_cidr[1]))
                else:
                    # print("deleting None network {} mask {}".format(ip_and_cidr[0], ip_and_cidr[1]))
                    ip.route("delete", dst=ip_and_cidr[0], mask=int(ip_and_cidr[1]))

            else:
                if action == 'add':
                    # print("adding network {} mask {} gateway {}".format(ip_and_cidr[0], ip_and_cidr[1],\
                    # gateway[count]))
                    ip.route("add", dst=ip_and_cidr[0], mask=int(ip_and_cidr[1]), gateway=gateway[count])
                else:
                    # print("deleting network {} mask {} gateway {}".format(ip_and_cidr[0], ip_and_cidr[1],\
                    # gateway[count]))
                    ip.route("delete", dst=ip_and_cidr[0], mask=int(ip_and_cidr[1]), gateway=gateway[count])

        ## FIXME
        except:
            print('invalid IP')

        finally:
            count += 1

def edit_specific_route(destination, gateway, netmask, action):
    if action == 'del' or action == 'add':
        
        ip = IPRoute()
        ip.route(action, dst=destination, mask=int(netmask_to_cidr(netmask)), gateway=gateway)
    


def check_if_valid_ipaddress_with_cidr(ip_cidr):
    if re.match(ip_cidr_regex, ip_cidr):
        return True
    else:
        print('Invalid IP address provided: {}'.format(ip_cidr))
        return False

def check_if_valid_ipaddress(ip):
    if re.match(ip_regex, ip):
        return True
    else:
        return False

def check_if_interface_exists(interface_name):
    exists = False
    for name in netifaces.interfaces():
        if interface_name == name:
            exists = True
    return exists

def compare_routing_tables(cidr, gateway, cidr2, gateway2):

    cidr_gateway_combo = list(zip(cidr, gateway))
    cidr_gateway_combo_2 = list(zip(cidr2, gateway2))

    return [[x for x in cidr_gateway_combo if x not in cidr_gateway_combo_2], [x for x in cidr_gateway_combo_2 \
                                                                               if x not in cidr_gateway_combo]]


def extract_hashes_from_ettercap_output():

    pattern = re.compile("OSPF-.*")

    # TODO could be a different path here

    for i, line in enumerate(open('/tmp/etter_hashes.txt')):
    # for i, line in enumerate(open('{}/etter_hashes.txt'.format(user_var.path))):
        for match in re.finditer(pattern, line):
            print(match.group())


def get_interface_netmask(interface):
    return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']

def check_if_interface_exists(interface):
    if interface in netifaces.interfaces():
        return True
    return False