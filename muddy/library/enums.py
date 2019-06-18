'''
    Author: Dinesha Ranathunga
    Version: 1.0
    Date: 10/12/2015
    Description: Enums.
'''

from muddy.library.osi_model.transport_layer import Port
import muddy.log as log


def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    enums['reverse_mapping'] = reverse
    return type('Enum', (), enums)

IcmpType = enum(echo_reply=0, dest_unreachable=3, source_quench=4, redirect=5, alt_host_address=7, echo=8, router_advert=9, router_select=10,
                time_exceeded=11, parameter_error=12, timestamp=13, timestamp_reply=14, info_request=15, info_reply=16, address_mask_request=17, address_mask_reply=18,
                traceroute=30, datagram_error=31, host_redirect=32, where_are_you=33, i_am_here=34, registration_request=35, registration_reply=36, domain_name_req=37,
                domain_name_reply=38, skip=39, photuris=40, max=255)

IcmpCode = enum(min=0, max=255)
PortNumbers = enum(min=Port(1), max=Port(65535), all=(Port(0),Port(65535)), dynamic=(Port(1024),Port(65535)), well_known=(Port(0),Port(1023)))

TLSProtocol = enum(SSLv3=1, TLSv1=2)
FtpOperationMode = enum(Active=1, Passive=2)

Ipv4ProtocolNumbers = enum(all=(0,255), icmp=1, tcp=6, udp=17, eigrp=88, ospf=89)
ProtocolAttributes=enum(tcp_dest_port='tcp.dest_port=',tcp_source_port='tcp.source_port=',
                        udp_dest_port='udp.dest_port=',udp_source_port='udp.source_port=',
                        icmp_type='icmp.type=',icmp_code='icmp.code=',comment='comment=')

ExportTargetPlatform=enum(plain_text=1,alloy=2,algebraic_model=3)

MatchCriteria = enum(ExactName=1, Function=2)

RuleEffect = enum(PermitTo=1, PermitToFrom=2, Deny=2)

NetworkDevice = enum(Host='host', Link='link', Switch='switch', Router='router', Firewall='firewall', Server="server")
GraphAttribute = enum(Type='device_type', SubType='device_subtype', Service='service', Exploits='exploits', Label='label', SubnetIpAddress='subnet_ip', SubnetMask='mask', IpAddress='ipaddress', VlanId='vlan_id', HostIds='host_ids', SwitchIds='switch_ids', RouterIds='router_ids', LinkIds='link_ids' ,ServerIds='server_ids', FirewallIds='firewall_ids',FirewallPaths='firewall_paths' )

SecurityElement = enum(Conduit="conduit", IndirectConduit="indirect_conduit", Zone="zone", AbstractZone='abstract_zone', FirewallZone='firewall_zone')

TargetPlatform=enum(Netkit=0, Cisco=1)

class ExportBase(object):
    def __init__(self):
        pass

    def Export(self, target_platform):
        if target_platform==ExportTargetPlatform.plain_text:
            log.info("Converting policy to plain_text")
        elif target_platform==ExportTargetPlatform.alloy:
            log.info("Converting policy to Alloy")
        elif target_platform==ExportTargetPlatform.algebraic_model:
            log.info("Converting policy to Algebraic model")
        return