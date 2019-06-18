% if policy:
{
  "ietf-mud:mud": {
    "mud-version": 1,
    "mud-url": "https://bms.example.com/.well-known/mud/${policy.device_name}",
    "last-update": "${policy.datetime}",
    "cache-validity": 48,
    "is-supported": true,
    "systeminfo": "${policy.device_desc} ",
    "from-device-policy": {
      "access-lists": {
        "access-list": [
<%
   index=1
   length = len(policy.from_acls)
%>
% for acl in policy.from_acls:
    % if index < length:
          {
            "name": "mud${index}-v4fr"
          },
    % else:
	  {
            "name": "mud${index}-v4fr"
          }
    % endif
<%
  index +=1
%>
% endfor
        ]
      }
    },
    "to-device-policy": {
      "access-lists": {
        "access-list": [
<%
index=1
length = len(policy.to_acls)
%>
% for acl in policy.to_acls:
    % if index < length:
          {
            "name": "mud${index}-v4to"
          },
    % else:
	  {
            "name": "mud${index}-v4to"
          }
    % endif
<%
index +=1
%>
% endfor
        ]
      }
    }
  },
  "ietf-access-control-list:access-lists": {
    "acl": [
<%
index=1
%>
% for acl in policy.to_acls:
          {
            "name": "mud${index}-v4to",
	    "type": "ipv4-acl-type",
            "aces": {
  <%
  k=1
  ace_count=len(acl.aces)
  %>
           "ace": [
  % for ace in acl.aces:
             {
	        "name": "ace${k}-todev",
                "matches": {
      % for source in ace.source:
        <%
          is_tuple = False
          is_mud_node = False
          if isinstance(source,tuple):
	     is_tuple = True
          if is_tuple and ('controller' in source[0] or 'local-networks' in source[0] or 'manufacturer' in source[0]):
     	     is_mud_node = True
	  elif not is_tuple and 'local-networks' in source:
	     is_mud_node = True
        %>
	% if is_tuple and is_mud_node:
	          "ietf-mud:mud": {
      	  	       "${source[0]}": [
	                "${source[1]}"
                  ]
                 },
       % elif is_mud_node:
                  "ietf-mud:mud": {
      	  	  "${source}": [
			null
                  ]
                 },
       % endif
      % endfor
      <%
        prot=None
        src=None
        if '*' not in ace.protocol: prot="valid"
        for source in ace.source:
	    if isinstance(source,tuple) and ('ietf-acldns:src-dnsname' in source[0] or 'source-ipv4-network' in source[0]): src=source
      %>
      % if prot:
                "l3": {
                  "ipv4": {
		% if src:
		    "${src[0]}": "${src[1]}",
		% endif
                    "protocol": ${ace.protocol}
                  }
      % else:
		"l2": {
                  "eth": {
                    "ethertype": ${ace.ethertype}
                  }
      % endif
      <%
        if (ace.protocol =='6' or ace.protocol =='17') and '*' not in ace.sports: sport="valid"
        else: sport=None
        if (ace.protocol =='6' or ace.protocol =='17') and '*' not in ace.dports: dport="valid"
        else: dport=None
      %>
      % if sport is None and dport is None:
                }
      % else:
                },
      % endif
      % if sport:
                "l4": {
                  "${ace.protocol_desc}": {
                    "ietf-mud:direction-initiated": "${ace.direction}",
                    "source-port-range-or-operator": {
                      "operator": "eq",
                      "port": ${ace.sports}
                    }
                  }
                }
      % endif
      % if dport:
                "l4": {
                  "${ace.protocol_desc}": {
                    "ietf-mud:direction-initiated": "${ace.direction}",
                    "destination-port-range-or-operator": {
                      "operator": "eq",
                      "port": ${ace.dports}
                    }
                  }
                }
      % endif
              },
              "actions": {
                "forwarding": "${ace.action}"
              }
      % if k < ace_count:
          },
      % else:
          }
      % endif
  <%
  k +=1
  %>
  % endfor
        ]
       }
     },
<%
index +=1
%>
% endfor
<%
index=1
length = len(policy.from_acls)
%>
% for acl in policy.from_acls:
          {
            "name": "mud${index}-v4fr",
	    "type": "ipv4-acl-type",
            "aces": {
  <%
  k=1
  ace_count=len(acl.aces)
  %>
           "ace": [
  % for ace in acl.aces:
             {
	        "name": "ace${k}-frdev",
                "matches": {
      % for dest in ace.dest:
        <%
          is_tuple=False
          is_mud_node=False
          if isinstance(dest,tuple):
	     is_tuple = True
          if is_tuple and ('controller' in dest[0] or 'local-networks' in dest[0] or 'manufacturer' in dest[0]):
     	     is_mud_node = True
	  elif not is_tuple and 'local-networks' in dest:
	     is_mud_node = True
        %>
        % if is_tuple and is_mud_node:
		"ietf-mud:mud": {
		   "${dest[0]}": [
	               "${dest[1]}"
                  ]
		 },
 	% elif is_mud_node:
		"ietf-mud:mud": {
                  "${dest}": [
			null
                  ]
		},
	% endif
      % endfor
      <%
        prot=None
        if '*' not in ace.protocol:
     	  prot="valid"

	dst=None
        for dest in ace.dest:
	    if isinstance(dest,tuple) and ('ietf-acldns:dst-dnsname' in dest[0] or 'destination-ipv4-network' in dest[0]):
               dst=dest
      %>
      % if prot:
                "l3": {
                  "ipv4": {
                % if dst:
		    "${dst[0]}": "${dst[1]}",
		% endif
                    "protocol": ${ace.protocol}
                  }
      % else:
		"l2": {
                  "eth": {
                    "ethertype": ${ace.ethertype}
                  }
      % endif
      <%
        sport=None
        if (ace.protocol =='6' or ace.protocol =='17') and '*' not in ace.sports:
     	  sport="valid"
	dport=None
        if (ace.protocol =='6' or ace.protocol =='17') and '*' not in ace.dports:
     	  dport="valid"
      %>
      % if sport is None and dport is None:
                }
      % else:
                },
      % endif
      % if sport:
                "l4": {
                  "${ace.protocol_desc}": {
                    "ietf-mud:direction-initiated": "${ace.direction}",
                    "source-port-range-or-operator": {
                      "operator": "eq",
                      "port": ${ace.sports}
                    }
                  }
                }
      % endif
      % if dport:
                "l4": {
                  "${ace.protocol_desc}": {
                    "ietf-mud:direction-initiated": "${ace.direction}",
                    "destination-port-range-or-operator": {
                      "operator": "eq",
                      "port": ${ace.dports}
                    }
                  }
                }
      % endif
              },
              "actions": {
                "forwarding": "${ace.action}"
              }
      % if k < ace_count:
          },
      % else:
          }
      % endif
  <%
  k +=1
  %>
  % endfor
        ]
       }
  % if index < length:
     },
  % else:
     }
  % endif
<%
index +=1
%>
% endfor
]
}
}
% endif
