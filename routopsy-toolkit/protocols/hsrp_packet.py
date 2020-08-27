class HSRP_PACKET:
    def __init__(self):
        self.source_mac = None
        self.source_ip = None 
        self.destination_mac = None
        self.destination_ip = None
        self.version = None
        self.state = None
        self.hello_interval = None
        self.dead_interval = None
        self.priority = None
        self.group = None
        self.authentication = None
        self.identifier = None
        self.virtual_ip = None
        self.vulnerbale = None

    def set_data(self, source_mac, source_ip, destination_mac, destination_ip, version, state, hello_interval, dead_interval, priority, group, authentication, identifier, virtual_ip, vulnerbale):
        self.source_mac = source_mac
        self.source_ip = source_ip 
        self.destination_mac = destination_mac
        self.destination_ip = destination_ip
        self.version = version
        self.state = state
        self.hello_interval = hello_interval
        self.dead_interval = dead_interval
        self.priority = priority
        self.group = group
        self.authentication = authentication
        self.identifier = identifier
        self.virtual_ip = virtual_ip
        self.vulnerbale = vulnerbale