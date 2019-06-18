class ServiceBase(object):

    def __init__(self, protocol, ports, flags):
        self.service_protocol = protocol
        self.flags = flags
        self.ports = ports
        #TODO: check if return path needs to be enabled
        self.enable_return_path = False

    @property
    def IsReturnPathEnabled(self):
        return self.enable_return_path

    @property
    def IsApplicationLayerFilteringEnabled(self):
        return self.enable_application_filtering

    @property
    def IsStatefulFilteringEnabled(self):
            return False
    
    @property
    def Protocol(self):
        return self.service_protocol

    @property
    def Ports(self):
        return self.ports