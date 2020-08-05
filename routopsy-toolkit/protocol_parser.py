def get_data_from_ospf_header(packet):
    areaId = packet['OSPF Header'].area

    return areaId


def get_data_from_layer_two_and_three(packet):
    sourceMac = packet['Ethernet'].src
    sourceIP = packet['IP'].src
    destinationMac = packet['Ethernet'].dst
    destinationIP = packet['IP'].dst

    return sourceMac, sourceIP, destinationMac, destinationIP


def get_data_from_hello_packet(packet):
    sourceMac, sourceIP, destinationMac, destinationIP = get_data_from_layer_two_and_three(packet)
    areaId = get_data_from_ospf_header(packet)
    helloInterval = packet['OSPF Hello'].hellointerval
    deadInterval = packet['OSPF Hello'].deadinterval
    router = packet['OSPF Hello'].router
    backup = packet['OSPF Hello'].backup
    mask = packet['OSPF Hello'].mask

    return sourceMac, sourceIP, destinationMac, destinationIP, areaId, helloInterval, deadInterval, router, backup, mask


def get_data_from_eigrp_hello_packet(packet):
    sourceMac, sourceIP, destinationMac, destinationIP = get_data_from_layer_two_and_three(packet)
    asn = packet['EIGRP'].asn
    holdInt = packet['EIGRPParam'].holdtime
    return sourceMac, sourceIP, destinationMac, destinationIP, asn, holdInt

def get_data_from_rip_response(packet):
    sourceMac, sourceIP, destinationMac, destinationIP = get_data_from_layer_two_and_three(packet)
    return sourceMac, sourceIP, destinationMac, destinationIP

def get_data_from_auth_rip_response(packet):
    sourceMac, sourceIP, destinationMac, destinationIP = get_data_from_layer_two_and_three(packet)
    # dodgy hack
    # print(packet['RIPAuth'].password.decode('UTF-8').rstrip('\x00'))
    password = packet['RIPAuth'].password.decode('UTF-8').rstrip('\x00')
    return sourceMac, sourceIP, destinationMac, destinationIP, password

