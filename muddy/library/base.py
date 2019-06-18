'''
    Author: Dinesha Ranathunga
    Version: 1.0
    Date: 10/12/2015
    Description: Collection of base classes.
'''

class NetworkElement(object):

    def __init__(self, id):
        self.id = id

    @property
    def Id(self):
        return self.id


class ProtocolBase(object):
    count = 0
    type = 'ProtocolBase (unspecified)'

    def __init__(self):
        self.count+=1

    def asciitree(self, prefix=''):
        '''Display an ascii tree of element'''
        result = "%s%s\n" % (prefix, repr(self))
        prefix += '|  '
        for c in self.__dict__:
            if isinstance(c,ProtocolBase):
                result += c.asciitree(prefix)
            elif isinstance(self.__dict__[c],list):
                for item in self.__dict__[c]:
                    if isinstance(item,ProtocolBase):
                        result += item.asciitree(prefix)
            if isinstance(self.__dict__[c],ProtocolBase):
                result += self.__dict__[c].asciitree(prefix)
        return result

    def __str__(self):
        return self.asciitree()

    def __repr__(self):
        return self.type

