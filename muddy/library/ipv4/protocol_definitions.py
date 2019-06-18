'''
    Author: Dinesha Ranathunga
    Version: 1.0
    Date: 10/12/2015
    Description: IP protocol definitions.
'''

from muddy.library.exception import ProtocolException
from muddy.library.properties import resources
from muddy.library.utilities import Util
from muddy.library.base import ProtocolBase
from muddy.library.osi_model.transport_layer import Port
from muddy.library.enums import PortNumbers, ProtocolAttributes, IcmpType, IcmpCode, Ipv4ProtocolNumbers

class Ip(ProtocolBase):
    def __init__(self):
        self.comment=None
        return

    @property
    def IpProtocol(self):
        return Ipv4ProtocolNumbers.all

    def IsIdenticalFunctionTo(self, comparison_obj):
        if isinstance(comparison_obj, Ip):
                return True
        return False

    def PopulateComment(self, attributes_list, valid_attributes):
        result=list()
        # non empty attribute list passed in, validate..
        attribute_values = Util.GetAttributeValues(attributes_list, valid_attributes)
        if Util.IsCommentAvailable(ProtocolAttributes.comment, attribute_values, result):
            self.comment = result[0]

    @property
    def IsStatefulFilteringEnabled(self):
        return False

    def __repr__(self):
        return "%s" % (type(self))

class TransportBase(Ip):
    def __init__(self, ip_protocol, attributes_list=None, valid_attributes=None, dest_port=None, source_port=None):
        self.ip_protocol=ip_protocol
        if attributes_list and len(attributes_list)>0:
            # set member defaults
            self.dest_port=[PortNumbers.dynamic]
            self.source_port=[PortNumbers.dynamic]

            # validate input attributes
            invalid_items= list()
            if Util.InvalidAttributesPresent(attributes_list, valid_attributes, invalid_items):
                raise ProtocolException('%s : %s'%(resources["protocol_attributes_invalid"], invalid_items[0]))
            # also check for same attributes specified multiple times
            if Util.DuplicateAttributesPresent(attributes_list, valid_attributes):
                raise ProtocolException('%s : %s'%(resources['duplicate_protocol_attributes'],attributes_list))

            # populate members from attributes
            try:
                self.PopulatePortDetails(attributes_list, valid_attributes)
                self.PopulateComment(attributes_list, valid_attributes)
                # TODO:: populate any tcp flags
                #if self.ip_protocol==Ipv4ProtocolNumbers.tcp:
                #    self.PopulateTcpFlags(attributes_list,valid_attributes)
            except AttributeError, e:
                raise ProtocolException(e.message)

        else:
            # set port values
            self.dest_port=dest_port
            self.source_port=source_port
            # TODO:: populate any tcp flags

        # final check for compliance
        if (Util.ArePortsEqual(self.dest_port,[PortNumbers.all]) and Util.ArePortsEqual(self.source_port,[PortNumbers.all]) or
            Util.ArePortsEqual(self.dest_port,[PortNumbers.all]) and Util.ArePortsEqual(self.source_port,[PortNumbers.dynamic]) or
            Util.ArePortsEqual(self.dest_port,[PortNumbers.dynamic]) and Util.ArePortsEqual(self.source_port,[PortNumbers.all]) or
            Util.ArePortsEqual(self.dest_port,[PortNumbers.dynamic]) and Util.ArePortsEqual(self.source_port,[PortNumbers.dynamic])):
            raise ProtocolException(resources["generic_services_disallowed"])

        return

    @property
    def IpProtocol(self):
        return self.ip_protocol

    @property
    def DynamicPorts(self):
        return PortNumbers.dynamic

    @property
    def WellKnownPorts(self):
        return PortNumbers.well_known

    @property
    def DestPort(self):
        return self.dest_port

    @property
    def SourcePort(self):
        return self.source_port

    @DestPort.setter
    def DestPort(self, dest_port):
        self.dest_port = dest_port

    @SourcePort.setter
    def SourcePort(self, source_port):
        self.source_port = source_port

    @property
    def State(self):
        return self.state

    @State.setter
    def State(self,state):
        self.state=state

    def PopulatePortDetails(self, attributes_list, valid_port_attributes):
        result=list()
        # non empty attribute list passed in, validate..
        attribute_values = Util.GetAttributeValues(attributes_list, valid_port_attributes)
        if Util.IsPortValueAvailable(ProtocolAttributes.tcp_dest_port, attribute_values, result):
            self.dest_port = result[0]
        elif Util.IsPortValueAvailable(ProtocolAttributes.udp_dest_port, attribute_values, result):
            self.dest_port = result[0]
        # clear list
        result=list()
        if Util.IsPortValueAvailable(ProtocolAttributes.tcp_source_port, attribute_values, result):
            self.source_port = result[0]
        elif Util.IsPortValueAvailable(ProtocolAttributes.udp_source_port, attribute_values, result):
            self.source_port = result[0]

    @property
    def IsStatefulFilteringEnabled(self):
        if self.IpProtocol == Ipv4ProtocolNumbers.tcp:
            return True
        else:
            return False

    def __repr__(self):
        return "%s" % (type(self))

class Tcp(TransportBase):

    def __init__(self, attributes_list, tcp_dest_port=[PortNumbers.dynamic], tcp_source_port=[PortNumbers.dynamic]):
        if attributes_list:
            # list of valid tcp attributes
            valid_tcp_attributes=[ProtocolAttributes.tcp_dest_port, ProtocolAttributes.tcp_source_port, ProtocolAttributes.comment]
            super(Tcp, self).__init__(Ipv4ProtocolNumbers.tcp, attributes_list=attributes_list, valid_attributes=valid_tcp_attributes)
        else:
            super(Tcp, self).__init__(Ipv4ProtocolNumbers.tcp, dest_port=tcp_dest_port, source_port=tcp_source_port)
        return

    def IsIdenticalFunctionTo(self, comparison_obj):
        if isinstance(comparison_obj, Tcp):
            if(Util.ArePortsEqual(comparison_obj.DestPort, self.DestPort) and
               Util.ArePortsEqual(comparison_obj.SourcePort, self.SourcePort)):
                return True
        return False

class Udp(TransportBase):

    def __init__(self, attributes_list, udp_dest_port=[PortNumbers.dynamic], udp_source_port=[PortNumbers.dynamic]):
        if attributes_list:
            # list of valid udp attributes
            valid_udp_attributes=[ProtocolAttributes.udp_dest_port, ProtocolAttributes.udp_source_port, ProtocolAttributes.comment]
            super(Udp, self).__init__(Ipv4ProtocolNumbers.udp, attributes_list=attributes_list, valid_attributes=valid_udp_attributes)
        else:
            super(Udp, self).__init__(Ipv4ProtocolNumbers.udp, dest_port=udp_dest_port, source_port=udp_source_port)
        return

    def IsIdenticalFunctionTo(self, comparison_obj):
        if isinstance(comparison_obj, Udp):
            if(Util.ArePortsEqual(comparison_obj.DestPort, self.DestPort) and
               Util.ArePortsEqual(comparison_obj.SourcePort, self.SourcePort)):
                return True
        return False

class Icmp(Ip):

    def __init__(self, attributes_list):

        # set member defaults
        # TODO: set default icmp type = echo?
        self.icmp_type = None
        self.icmp_code = None

        if not attributes_list or len(attributes_list)==0 :
            raise AttributeError(resources['protocol_attributes_invalid'])

        # list of valid icmp attributes
        valid_attributes=[ProtocolAttributes.icmp_type, ProtocolAttributes.icmp_code, ProtocolAttributes.comment]

        # validate input attributes
        invalid_items= list()
        if Util.InvalidAttributesPresent(attributes_list, valid_attributes, invalid_items):
            raise ProtocolException('%s : %s'%(resources["protocol_attributes_invalid"], invalid_items[0]))

        # populate members from attributes
        try:

            result=list()
            attribute_values = Util.GetAttributeValues(attributes_list, valid_attributes)
            if Util.IsIcmpTypeValueAvailable(ProtocolAttributes.icmp_type, attribute_values, result):
                self.icmp_type = result[0]
            else:
                # invalid
                raise ProtocolException("%s"%(resources["icmp_type_not_specified"]))
            self.PopulateComment(attributes_list, valid_attributes)
            # clear list
            result=list()
            if Util.IsIcmpCodeValueAvailable(ProtocolAttributes.icmp_code, attribute_values, result):
                self.icmp_code = result[0]
        except AttributeError, e:
            raise ProtocolException(e.message)

        # final check for compliance?
        return

    @property
    def IpProtocol(self):
        return Ipv4ProtocolNumbers.icmp

    def IsIdenticalFunctionTo(self, comparison_obj):
        if isinstance(comparison_obj, Icmp):
            if(comparison_obj.icmp_type == self.icmp_type and
               comparison_obj.icmp_code == self.icmp_code):
                return True
        return False

    @property
    def Type(self):
        return self.icmp_type

    @Type.setter
    def Type(self, icmp_type):
        self.icmp_type = icmp_type

    @property
    def Code(self):
        return self.icmp_code

    @Type.setter
    def Code(self, icmp_code):
        self.icmp_code = icmp_code

    def __repr__(self):
        return "%s" % (type(self))

class Eigrp(Ip):
    def __init__(self, attributes_list):

        # list of valid icmp attributes
        valid_attributes=[ProtocolAttributes.comment]

        # validate input attributes
        invalid_items= list()
        if Util.InvalidAttributesPresent(attributes_list, valid_attributes, invalid_items):
            raise ProtocolException('%s : %s'%(resources["protocol_attributes_invalid"], invalid_items[0]))

        # populate members from attributes
        try:
            self.PopulateComment(attributes_list, valid_attributes)
        except AttributeError, e:
            raise ProtocolException(e.message)

        return

    def IsIdenticalFunctionTo(self, comparison_obj):
        if isinstance(comparison_obj, Eigrp):
                return True
        return False

    @property
    def IpProtocol(self):
        return Ipv4ProtocolNumbers.eigrp

    def __repr__(self):
        return "%s" % (type(self))

class Ospf(Ip):
    def __init__(self, attributes_list):

        # list of valid icmp attributes
        valid_attributes=[ProtocolAttributes.comment]

        # validate input attributes
        invalid_items= list()
        if Util.InvalidAttributesPresent(attributes_list, valid_attributes, invalid_items):
            raise ProtocolException('%s : %s'%(resources["protocol_attributes_invalid"], invalid_items[0]))

        # populate members from attributes
        try:
            self.PopulateComment(attributes_list, valid_attributes)
        except AttributeError, e:
            raise ProtocolException(e.message)

        return

    @property
    def IpProtocol(self):
        return Ipv4ProtocolNumbers.ospf

    def IsIdenticalFunctionTo(self, comparison_obj):
        if isinstance(comparison_obj, Ospf):
                return True
        return False

    def __repr__(self):
        return "%s" % (type(self))



