'''
    Author: Dinesha Ranathunga
    Version: 1.0
    Date: 10/12/2015
    Description: transport layer specific classes.
'''

from muddy.library import properties, exception
from muddy.library.base import ProtocolBase

class Port(ProtocolBase):
    def __init__(self, number):
        # set default
        self.port_number=None
        # validate
        if not (number >= 0 and number <= 65535):
            raise exception.ArgumentException(properties.resources['port_number_invalid'])
        self.port_number=number

    @property
    def Number(self):
        return self.port_number

    def __repr__(self):
        return "%s: %s" % (type(self),self.port_number)