class VRRP_PACKET:
    def __init__(self):
        self.source_mac = None
        self.source_ip = None 
        self.destination_mac = None
        self.destination_ip = None
        self.virtual_router_id = None
        self.priority = None
        self.virtual_ip_address = None
        self.authentication_type = None
        self.authentication_password = None
        self.ip_count = None
        self.advertisement_interval = None
        self.vulnerable = False
    
    def set_data(self, source_mac, source_ip, destination_mac, destination_ip, virtual_router_id, priority, virtual_ip_address, authentication_type, authentication_password, ip_count, advertisement_interval, vulnerable):
        self.source_mac = source_mac
        self.source_ip = source_ip 
        self.destination_mac = destination_mac
        self.destination_ip = destination_ip
        self.virtual_router_id = virtual_router_id
        self.priority = priority
        self.virtual_ip_address = virtual_ip_address
        self.authentication_type = authentication_type
        self.authentication_password = authentication_password
        self.ip_count = ip_count
        self.advertisement_interval = advertisement_interval
        self.vulnerable = vulnerable