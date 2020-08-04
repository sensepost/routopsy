class RIP_PACKET:
    def __init__(self):
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
        self.source_mac = None
        self.source_ip = None
        self.destination_mac = None
        self.destination_ip = None
        self.authentication_type = None
        self.password = None
        self.neighbours = []
        self.vulnerable = False
        self.version = None

    def set_data(self, source_mac, source_ip, destination_mac, destination_ip, authentication_type, password, version, vulnerable):
        self.source_mac = source_mac
        self.source_ip = source_ip
        self.destination_mac = destination_mac
        self.destination_ip = destination_ip
        self.authentication_type = authentication_type
        self.password = password
        self.vulnerable = vulnerable
        self.version = version