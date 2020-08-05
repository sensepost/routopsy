class Data:
    def __init__(self):
        self.interface = None
        self.count = None
        self.inject = None
        self.ipaddress = None
        self.scan = None
        self.attack = None
        self.protocol = None
        self.path = None
        self.target = None
        self.redirect = None
        self.redirectaddresses = None
        self.inject_local_ip_addresses = None
        self.redirect_local_ip_addresses = None
        self.redirect_local = False
        self.inject_local = False
        self.clean = None
        self.attack_count = None
        self.password = None

    def set_data(self, interface, count, inject, ipaddress, scan, attack, protocol, path, target, redirect, redirectaddresses, clean, attack_count, inject_local, inject_local_ip_addresses, redirect_local, redirect_local_ip_addresses, password):
        self.interface = interface
        self.count = count
        self.inject = inject
        self.ipaddress = ipaddress
        self.scan = scan
        self.attack = attack
        self.protocol = protocol
        self.path = path
        self.target = target
        self.redirect = redirect
        self.redirectaddresses = redirectaddresses
        self.clean = clean
        self.attack_count = attack_count
        self.inject_local_ip_addresses = inject_local_ip_addresses
        self.redirect_local_ip_addresses = redirect_local_ip_addresses
        self.redirect_local = redirect_local
        self.inject_local = inject_local
        self.password = password