class EIGRP_PACKET:
    def __init__(self):
        # - sourceMac       [0]
        # - sourceIP        [1]
        # - destinationMac  [2]
        # - destinationIP   [3]
        # - asn             [4]
        # - hold_interval   [5]
        self.source_mac = None
        self.source_ip = None
        self.destination_mac = None
        self.destination_ip = None
        self.asn = None
        self.hold_interval = None
        self.neighbours = []
        self.vulnerable = False

    def set_data(self, source_mac,source_ip, destination_mac, destination_ip, asn, hold_interval, vulnerable):
        self.source_mac = source_mac
        self.source_ip = source_ip
        self.destination_mac = destination_mac
        self.destination_ip = destination_ip
        self.asn = asn
        self.hold_interval = hold_interval
        self.vulnerable = vulnerable