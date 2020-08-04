from netaddr import IPAddress
from netaddr import IPNetwork

import os
from shutil import copyfile

from state import ospf_packet
from state import eigrp_packet
from state import user_var

import netifaces

import colorama
from colorama import Fore, Back, Style
colorama.init(autoreset=True)

def tempGetIP():
    dict = netifaces.ifaddresses(user_var.interface)
    for x in dict.get(2):
        y = x.get('addr')
    return y + '/32'


def build_ospf_config():

    #tempGetIP()
    #print("debug")

    cidr = IPAddress(ospf_packet.mask).netmask_bits()
    ip_range = IPNetwork(ospf_packet.source_ip + '/' + str(cidr))

    if not os.path.exists(user_var.path):
        print(Fore.YELLOW + Style.BRIGHT + "[-]Provided path does not exist.")
        try:
            os.mkdir(user_var.path)
        except OSError:
            print("Creation of the path {} failed. Could not create configuration files.".format(user_var.path))
            return

    copyfile('daemons', '{}/daemons'.format(user_var.path))
    
    ospfd_config = open('{}/ospfd.conf'.format(user_var.path), 'w')
    ospfd_config.write('!\n')
    #ospfd_config.write('interface {}\n'.format(user_var.interface))
    #ospfd_config.write(' ip ospf hello-interval {}\n'.format(ospf_packet.hello_interval))
    #ospfd_config.write(' ip ospf dead-interval {}\n'.format(ospf_packet.dead_interval))
    #ospfd_config.write('!\n')
    ospfd_config.write('router ospf\n')
    #ospfd_config.write(' network ' + str(ip_range.network) + '/' + str(cidr) + ' area ' + ospf_packet.area_id + '\n')
    ospfd_config.write(' network ' + tempGetIP() + ' area ' + ospf_packet.area_id + '\n')
    ospfd_config.write('!\n')

    if user_var.inject:
        for ip in user_var.ipaddress:
            ospfd_config.write(' network {}/32'.format(ip) + ' area ' + ospf_packet.area_id + '\n')
        interface_config = open('{}/zebra.conf'.format(user_var.path), 'w')
        interface_config.write('!\n')
        interface_config.write('interface lo\n')
        for ip in user_var.ipaddress:
            interface_config.write(' ip address {}/32\n'.format(ip))
        interface_config.close()

    ospfd_config.close()

def build_eigrp_config():

    if not os.path.exists(user_var.path):
        print(Fore.YELLOW + Style.BRIGHT + "[-]Provided path does not exist.")
        try:
            os.mkdir(user_var.path)
        except OSError:
            print("Creation of the path {} failed. Could not create configuration files.".format(user_var.path))
            return

    copyfile('daemons', '{}/daemons'.format(user_var.path))

    eigrpd_config = open('{}/eigrpd.conf'.format(user_var.path), 'w')
    eigrpd_config.write('!\n')
    eigrpd_config.write('router eigrp ' + str(eigrp_packet.asn ) + '\n')
    #eigrpd_config.write(' network 0.0.0.0/0\n')
    eigrpd_config.write(' network ' + tempGetIP() + '\n')
    eigrpd_config.write('!\n')

    if user_var.inject:
        for ip in user_var.ipaddress:
            eigrpd_config.write(' network {}/32'.format(ip) + '\n')
        interface_config = open('{}/zebra.conf'.format(user_var.path), 'w')
        interface_config.write('!\n')
        interface_config.write('interface lo\n')
        for ip in user_var.ipaddress:
            interface_config.write(' ip address {}/32\n'.format(ip))
        interface_config.close()

    eigrpd_config.close()

def build_rip_config():

    if not os.path.exists(user_var.path):
        print(Fore.YELLOW + Style.BRIGHT + "[-]Provided path does not exist.")
        try:
            os.mkdir(user_var.path)
        except OSError:
            print("Creation of the path {} failed. Could not create configuration files.".format(user_var.path))
            return

    copyfile('daemons', '{}/daemons'.format(user_var.path))

    ripd_config = open('{}/ripd.conf'.format(user_var.path), 'w')
    ripd_config.write('!\n')
    ripd_config.write('router rip\n')
    #ripd_config.write(' network 0.0.0.0/0\n')
    ripd_config.write(' network ' + tempGetIP() + '\n')
    ripd_config.write('!\n')

    if user_var.inject:
        for ip in user_var.ipaddress:
            ripd_config.write(' network {}/32'.format(ip) + '\n')
        interface_config = open('{}/zebra.conf'.format(user_var.path), 'w')
        interface_config.write('!\n')
        interface_config.write('interface lo\n')
        for ip in user_var.ipaddress:
            interface_config.write(' ip address {}/32\n'.format(ip))
        interface_config.close()

    ripd_config.close()