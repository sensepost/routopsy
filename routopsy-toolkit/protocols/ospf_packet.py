class OSPF_PACKET:
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
        self.area_id = None
        self.hello_interval = None
        self.dead_interval = None
        self.router = None
        self.backup = None
        self.mask = None
        self.neighbours = []
        self.vulnerable = False
        self.authtype = None
        self.authdata = None
    
    def set_data(self, source_mac, source_ip, destination_mac, destination_ip, area_id, hello_interval, dead_interval, router, backup, mask, authtype, authdata, vulnerable):
        self.source_mac = source_mac
        self.source_ip = source_ip 
        self.destination_mac = destination_mac
        self.destination_ip = destination_ip
        self.area_id = area_id
        self.hello_interval = hello_interval
        self.dead_interval = dead_interval
        self.router = router
        self.backup = backup
        self.mask = mask
        self.vulnerable = vulnerable
        self.authtype = authtype
        self.authdata = authdata