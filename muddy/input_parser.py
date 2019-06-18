from os.path import isabs
from library.properties import resources
from library.exception import OutputPathInvalidException
from mgtoolkit.library import CanonicalPolicyHelper, MetagraphHelper, ConditionalMetagraph, MudPolicy, ACE, ACL, Edge
from mako.template import Template
import console_script as amodule
import os, csv
import datetime
import pytz
import log as log
import sys

def Singleton(cls):
    instances = {}
    def GetInstance():
        if cls not in instances:
            instances[cls] = cls()
        return instances[cls]
    return GetInstance

@Singleton
class InputParser(object):

    def create_mud_files(self,csv_file_path):

        try:
            template_path = os.path.dirname(amodule.__file__) + "/templates/"
            csv_path = csv_file_path
            default_csv_path=os.getcwd()
            if not isabs(csv_file_path): csv_path = default_csv_path + '/' + csv_file_path

            path_sep = os.path.sep
            components = csv_path.split(path_sep)
            parent_folder = path_sep.join(components[:-1])
            self.output_path = os.path.join(parent_folder,'results/')
            files = [x for x in os.listdir(csv_path)]

            for filename in files:
                log.info('generating MUD file for: %s ...'%filename)
                full_path_name = os.path.join(csv_path,filename)
                common_flows_lookup=dict()
                with open(full_path_name, 'rb') as csvfile:
                    data = self.read_file(full_path_name)
                    index=0
                    filename_with_ext = os.path.basename(full_path_name)
                    device_name, extension = os.path.splitext(filename_with_ext)

                    for row in data:
                        if index==0:
                            # omit header
                            index+=1
                            continue

                        index+=1
                        source_mac = row[0]
                        dest_mac = row[1]
                        ether_type= int(row[2],16)

                        source_ipaddresses = self.extract_ipaddresses(row[3])
                        dest_ipaddresses = self.extract_ipaddresses(row[4])

                        protocol = row[5]
                        source_ports = row[6]
                        dest_ports = row[7]

                        if device_name is not None and device_name not in common_flows_lookup:
                            common_flows_lookup[device_name]=[]

                        for source_ipaddr in source_ipaddresses:
                            for dest_ipaddr in dest_ipaddresses:
                                if source_ipaddr=='*' and dest_ipaddr=='*':
                                    # MAC based rules
                                    ace = ACE(source_mac,dest_mac,protocol,dest_ports,source_ports,'accept',ethertype=ether_type)
                                else:
                                    # ip based rules
                                    ace = ACE(source_ipaddr,dest_ipaddr,protocol,dest_ports,source_ports,'accept',ethertype=ether_type)

                                common_flows_lookup[device_name].append(ace)

                from_acls=[]
                to_acls=[]
                acl_from1=ACL("from")
                acl_to1=ACL("to")

                for entry_list in common_flows_lookup.values():
                    for entry in entry_list:
                        if '*' in entry.source and '<deviceMac>' not in entry.dest:
                            dest_groups=[]
                            if self.local_gateway_ipaddr in entry.dest:
                                # device to local gateway
                                dest_groups.append(('controller', 'urn:ietf:params:mud:gateway'))
                            elif CanonicalPolicyHelper().is_private_ipaddress(entry.dest):
                                # device to local app
                                dest_groups.append('local-networks')
                            elif self.is_domain_name(entry.dest):
                                # device to cloud..retain domain names
                                items = entry.dest.split(',')
                                for name in items:
                                   is_manufacturer=False
                                   for manufacturer in self.manufacturers:
                                      if manufacturer in entry.dest and ('manufacturer', name) not in dest_groups:
                                         dest_groups.append(('manufacturer', name))
                                         is_manufacturer=True
                                   if not is_manufacturer and CanonicalPolicyHelper().is_public_ipaddress(name) and ('destination-ipv4-network', '%s/32'%(name)) not in dest_groups:
                                     dest_groups.append(('destination-ipv4-network', '%s/32'%(name)))
                                   elif not is_manufacturer and ('ietf-acldns:dst-dnsname', name) not in dest_groups:
                                         dest_groups.append(('ietf-acldns:dst-dnsname', name))
                                   #elif not is_manufacturer:
                                   #    print('unhandled name1: %s'%name)
                            else:
                                   log.warning('omit(destination uknown): %s'%entry.dest)

                            if len(dest_groups)>0:
                                ace = ACE('device',dest_groups,entry.protocol,entry.dports,entry.sports,entry.action,"from-device",ethertype=entry.ethertype)
                                acl_from1.add_ace(ace)

                        elif '*' in entry.dest and '<deviceMac>' not in entry.source:
                            source_groups=[]
                            if self.local_gateway_ipaddr in entry.source:
                                # local gateway to device
                                source_groups.append(('controller', 'urn:ietf:params:mud:gateway'))
                            elif CanonicalPolicyHelper().is_private_ipaddress(entry.source) :
                                # local app to device
                                source_groups.append('local-networks')
                            elif self.is_domain_name(entry.source):
                                # cloud to device..retain domain names
                                items = entry.source.split(',')
                                for name in items:
                                    is_manufacturer=False
                                    for manufacturer in self.manufacturers:
                                        if manufacturer in entry.source and ('manufacturer', name) not in source_groups:
                                            source_groups.append(('manufacturer', name))
                                            is_manufacturer=True
                                    if not is_manufacturer and CanonicalPolicyHelper().is_public_ipaddress(name) and ('source-ipv4-network', '%s/32'%(name)) not in source_groups:
                                        source_groups.append(('source-ipv4-network', '%s/32'%(name)))
                                    elif not is_manufacturer and ('ietf-acldns:src-dnsname', name) not in source_groups:
                                        source_groups.append(('ietf-acldns:src-dnsname', name))
                                    #elif not is_manufacturer:
                                    #   print('unhandled name2: %s'%name)
                            else:
                                   log.warning('omit(source unknown): %s'%entry.source)

                            if len(source_groups)>0:
                                ace = ACE(source_groups,'device',entry.protocol,entry.dports,entry.sports,entry.action,"to-device",ethertype=entry.ethertype)
                                acl_to1.add_ace(ace)

                        elif '<deviceMac>' in entry.source:
                            dest_groups=[]
                            if '*' in entry.dest:
                                # device to local app
                                dest_groups.append('local-networks')
                            elif '<gatewayMac>' in entry.dest:
                                # device to local gateway
                                dest_groups.append(('controller', 'urn:ietf:params:mud:gateway'))
                            else:
                                log.warning('invalid entry.dest: src= %s, dst= %s, prot: %s, dports: %s, sports: %s, ethertype: %s'%(entry.source, entry.dest, entry.protocol,entry.dports,entry.sports,entry.ethertype))

                            if len(dest_groups)>0:
                                ace = ACE('device',dest_groups,entry.protocol,entry.dports,entry.sports,entry.action,"from-device",ethertype=entry.ethertype)
                                acl_from1.add_ace(ace)

                        elif '<deviceMac>' in entry.dest:
                            source_groups=[]
                            if '*' in entry.source:
                                # local app to device
                                source_groups.append('local-networks')
                            elif '<gatewayMac>' in entry.source:
                                # local gateway to device
                                source_groups.append(('controller', 'urn:ietf:params:mud:gateway'))
                            else:
                                log.warning('invalid entry.source: src= %s, dst= %s, prot: %s, dports: %s, sports: %s, ethertype: %s'%(entry.source, entry.dest, entry.protocol,entry.dports,entry.sports,entry.ethertype))

                            if len(source_groups)>0:
                                ace = ACE(source_groups,'device',entry.protocol,entry.dports,entry.sports,entry.action,"to-device",ethertype=entry.ethertype)
                                acl_to1.add_ace(ace)

                        else:
                            log.warning('invalid entry: %s'% entry)


                from_acls.append(acl_from1)
                to_acls.append(acl_to1)

                create_datetime = datetime.datetime.now(pytz.utc).isoformat()
                desc=device_name.replace('rule','').lower()
                mud_policy = MudPolicy(create_datetime,desc,desc,from_acls,to_acls)

                # construct MUD file
                mud_template = Template(filename=template_path+"mud_profile_template.mako")
                mud_policy_text = mud_template.render(policy=mud_policy)

                # create new folder
                subfolder= device_name.replace('rule','')
                target_folder = os.path.join(self.output_path, subfolder)
                if not os.path.exists(target_folder):
                   os.makedirs(target_folder)

                # write to file
                policy_file=open(os.path.join(target_folder,'device_mud_profile.json'),'w') #
                policy_file.write(mud_policy_text)
                policy_file.close()

        except BaseException, e:
            log.error('error:: %s'%e)

    def check_mud_consistency(self,output_path):
        import copy
        import json

        try:
            self.output_path = output_path
            default_output_path=os.getcwd()
            if not isabs(self.output_path): self.output_path = default_output_path + '/' + output_path

            if not isabs(self.output_path):
                raise OutputPathInvalidException(resources['output_path_invalid'])

            folders = [x for x in os.listdir(self.output_path) if '.' not in x]

            for folder in folders:
                full_folder_name = os.path.join(self.output_path,folder)
                files = [x for x in os.listdir(full_folder_name) if '.json' in x]

                filename=os.path.join(full_folder_name,files[0])
                log.info('parsing MUD file: %s ...'%filename)
                extracted = None
                with open(filename) as json_data:
                    extracted = json.load(json_data)

                acl_details =  MetagraphHelper().get_device_acl_details(extracted)

                # create metagraphs
                variables_set=set()

                vars=[]
                props=[]
                edge_list2 = self.get_edge_list(acl_details,vars,props)
                for var in vars:
                    variables_set=variables_set.union(var)
                propositions_set=set(props)
                cmg2 = ConditionalMetagraph(variables_set,propositions_set)
                cmg2.add_edges_from(edge_list2)

                vars=[]
                props=[]
                variables_set=set()
                edge_list = self.get_edge_list(acl_details,vars,props,convert_ipaddresses_to_numeric=True)
                for var in vars:
                    variables_set=variables_set.union(var)
                propositions_set=set(props)
                cmg = ConditionalMetagraph(variables_set,propositions_set)
                cmg.add_edges_from(edge_list)

                edge_list=[]
                id=0
                import socket
                for direction, acls in acl_details.iteritems():
                    for acl in acls:
                        if direction=='from':
                            invertex = set([acl.source])
                            dest=list(acl.dest)[0]
                            if self.is_domain_name(dest):
                               ipaddress = '%s/32'%socket.gethostbyname(dest.strip())
                               outvertex = set(MetagraphHelper().get_ipaddresses_numeric(set([ipaddress])))
                            else:
                               outvertex = set(MetagraphHelper().get_ipaddresses_numeric(set(acl.dest)))

                        elif direction=='to':
                            outvertex = set([acl.dest])
                            source=list(acl.source)[0]
                            if self.is_domain_name(source):
                               ipaddress = '%s/32'%socket.gethostbyname(source.strip())
                               invertex = set(MetagraphHelper().get_ipaddresses_numeric(set([ipaddress])))
                            else:
                               invertex = set(MetagraphHelper().get_ipaddresses_numeric(set(acl.source)))

                        attributes = []
                        attributes.append('protocol=%s'%acl.protocol)
                        dports = MetagraphHelper().get_port_descriptor(acl.protocol, acl.dports, 'dport')
                        sports = MetagraphHelper().get_port_descriptor(acl.protocol, acl.sports, 'sport')
                        if dports is not None:
                            attributes.append(dports)
                        if sports is not None:
                            attributes.append(sports)
                        attributes.append('action=%s'%acl.action)
                        # tag edge id
                        edge_id = 'edge%s'%id
                        propositions_set = propositions_set.union(attributes)
                        variables_set = variables_set.union(invertex)
                        variables_set = variables_set.union(outvertex)
                        edge = Edge(invertex,outvertex,attributes,label=edge_id)
                        edge_list.append(edge)
                        id+=1

                variables_set=variables_set.difference({'device'})
                non_overlapping_ipaddress_ranges = MetagraphHelper().get_minimal_non_overlapping_ipaddress_ranges(list(variables_set))

                converted=[]
                for ipaddr_range in non_overlapping_ipaddress_ranges:
                    range_string = '%s-%s'%(ipaddr_range[0],ipaddr_range[1])
                    converted.append(range_string)

                variable_set = set(converted)
                new_edge_list=[]
                for edge in edge_list:
                    edge_attributes= copy.copy(edge.attributes)

                    inv_device=False
                    outv_device=False
                    invertex = edge.invertex.difference(edge_attributes)
                    outvertex = edge.outvertex

                    if 'device' in invertex:
                        inv_device=True
                        invertex = invertex.difference({'device'})
                    if 'device' in outvertex:
                        outv_device=True
                        outvertex = outvertex.difference({'device'})

                    if len(invertex)>0:
                        invertex = MetagraphHelper().get_ipaddresses_canonical_form(invertex, non_overlapping_ipaddress_ranges)
                    if len(outvertex)>0:
                        outvertex = MetagraphHelper().get_ipaddresses_canonical_form(outvertex, non_overlapping_ipaddress_ranges)

                    if inv_device:
                        invertex = invertex.union({'device'})
                    if outv_device:
                        outvertex = outvertex.union({'device'})

                    temp= edge.attributes
                    new_edge= Edge(invertex, outvertex, temp, label=edge.label)
                    new_edge_list.append(new_edge)

                variable_set = variable_set.union({'device'})

                # create intermediate metagraph suitable for performing analysis
                converted_cmg= ConditionalMetagraph(variable_set, propositions_set)
                converted_cmg.add_edges_from(new_edge_list)

                # check for duplicates
                if len(new_edge_list)!= len(converted_cmg.edges):
                    duplicates = self.get_duplicate_edges(new_edge_list)
                    count=1
                    for edge in duplicates:
                        log.info('%s. duplicate edge: %s'%(count,str(edge)))
                        count+=1

                filepath= os.path.join(full_folder_name,'cmg_mud_profile.dot')
                MetagraphHelper().generate_visualisation(new_edge_list,filepath,display_attributes=False, use_temp_label=True)

                #mg_image_file =os.path.join(full_folder_name,'cmg_mud_profile.png')
                #(graph,) = pydot.graph_from_dot_file(filepath)
                #graph.write_png(mg_image_file)

                # 'generating complexity reduced, equivalent metagraph..'
                group_name_index=1
                new_edge_list=[]
                new_var_set=set()
                invertex_element_group_lookup=dict()
                outvertex_element_group_lookup=dict()

                for edge in converted_cmg.edges:
                    invertex_elts = list(edge.invertex.difference(converted_cmg.propositions_set))
                    outvertex_elts = list(edge.outvertex.difference(converted_cmg.propositions_set))

                    for elt in invertex_elts:
                        result= converted_cmg.get_associated_edges(elt)
                        edge_list_string=repr(result)
                        if edge_list_string not in invertex_element_group_lookup:
                            invertex_element_group_lookup[edge_list_string]=[]
                        if elt not in invertex_element_group_lookup[edge_list_string]:
                            invertex_element_group_lookup[edge_list_string].append(elt)

                    for elt in outvertex_elts:
                        result= converted_cmg.get_associated_edges(elt)
                        edge_list_string=repr(result)
                        if edge_list_string not in outvertex_element_group_lookup:
                            outvertex_element_group_lookup[edge_list_string]=[]
                        if elt not in outvertex_element_group_lookup[edge_list_string]:
                            outvertex_element_group_lookup[edge_list_string].append(elt)

                group_details_lookup=dict()

                for edge_list_string, elt_list in invertex_element_group_lookup.iteritems():
                    group_elts = set(elt_list)
                    if len(group_elts)>1:
                        # group
                        group_elts_string = json.dumps(list(group_elts))
                        if group_elts_string not in group_details_lookup:
                            group_name= 'group_%s'%group_name_index
                            group_details_lookup[group_elts_string]=group_name
                            group_name_index+=1

                for edge_list_string, elt_list in outvertex_element_group_lookup.iteritems():
                    group_elts = set(elt_list)
                    if len(group_elts)>1:
                        # group
                        group_elts_string = json.dumps(list(group_elts))
                        if group_elts_string not in group_details_lookup:
                            group_name= 'group_%s'%group_name_index
                            group_details_lookup[group_elts_string]=group_name
                            group_name_index+=1

                # replace original invertices with groups
                for edge in converted_cmg.edges:
                    invertex_elts = list(edge.invertex.difference(converted_cmg.propositions_set))
                    outvertex_elts = list(edge.outvertex)
                    new_invertex=set()
                    new_outvertex=set()

                    for group_elts, group_name in group_details_lookup.iteritems():
                        group_elts_list = json.loads(group_elts)
                        group_elts_list = [elt2.encode('ascii', errors='backslashreplace') for elt2 in group_elts_list]
                        if set(group_elts_list).issubset(set(invertex_elts)):
                            new_invertex = new_invertex.union({group_name})
                            invertex_elts = list(set(invertex_elts).difference(set(group_elts_list)))

                    for group_elts, group_name in group_details_lookup.iteritems():
                        group_elts_list = json.loads(group_elts)
                        group_elts_list = [elt2.encode('ascii', errors='backslashreplace') for elt2 in group_elts_list]
                        if set(group_elts_list).issubset(set(outvertex_elts)):
                            new_outvertex = new_outvertex.union({group_name})
                            outvertex_elts = list(set(outvertex_elts).difference(set(group_elts_list)))

                    new_invertex=new_invertex.union(set(invertex_elts))
                    new_outvertex=new_outvertex.union(set(outvertex_elts))
                    new_var_set = new_var_set.union(new_invertex)
                    new_var_set = new_var_set.union(new_outvertex)
                    new_edge_list.append(Edge(new_invertex, new_outvertex,
                                                      attributes=list(edge.invertex.intersection(converted_cmg.propositions_set)),
                                                      label=edge.label))

                # create complexity reduced, equivalent metagraph
                reduced_cmg= ConditionalMetagraph(new_var_set, converted_cmg.propositions_set)
                reduced_cmg.add_edges_from(new_edge_list)

                log.info('check metagraph for intent-ambiguous rules ...')
                conflicts = reduced_cmg.check_conflicts()
                if conflicts is None or len(conflicts)==0:
                    log.info('NO intent-ambiguous rules found')
                else:
                    count=1
                    for mp in conflicts:
                       conflicting_edges = MetagraphHelper().conflict_source_lookup[mp]
                       for edge_tuple in conflicting_edges:
                           conflict_source_desc= '.'.join(edge_tuple[2])
                           log.info("%s. policy conflicts detected:: cause- %s"%(count,conflict_source_desc))
                           count+=1
                           self.print_edge(edge_tuple[0])
                           self.print_edge(edge_tuple[1])

                log.info('check metagraph for redundant rules...')
                redundancies = reduced_cmg.check_redundancies()
                if redundancies is None or len(redundancies)==0:
                    log.info('NO redundancies found')
                else:
                    count=1
                    for redundancy in redundancies:
                       log.info("redundancy %s"%count)
                       log.info("edge0- %s"%(str(redundancy[0])))
                       log.info("edge1- %s"%(str(redundancy[1])))
                       count+=1

        except BaseException,e:
            log.error('check_mud_consistency:: %s'%(e))

    def check_bp_compliance(self, mud_file_path):
        import json
        import os
        from mgtoolkit.library import CanonicalPolicyHelper

        try:

            # read in MUD file
            file = mud_file_path
            default_mud_path=os.getcwd()
            if not isabs(mud_file_path): file = default_mud_path + '/' + mud_file_path

            extracted = None
            with open(file) as json_data:
                extracted = json.load(json_data)

            acl_details =  MetagraphHelper().get_device_acl_details(extracted,True)

            # create metagraphs
            vars=[]
            props=[]
            variables_set=set()

            edge_list = self.get_edge_list(acl_details,vars,props,convert_ipaddresses_to_numeric=True)
            for var in vars:
                variables_set=variables_set.union(var)
            propositions_set=set(props)
            cmg = ConditionalMetagraph(variables_set,propositions_set)
            cmg.add_edges_from(edge_list)

            # check MUD policy is equally or more restrictive than SCADA
            #log.info('create line digraph of MUD policy..')
            digraph_original = MetagraphHelper().GetMultiDigraph(cmg)
            cmg_original_line_graph=MetagraphHelper().CreateLineGraph(digraph_original)

            #log.info('create line digraph of SCADA best practice policy..')
            digraph_bp_policy = MetagraphHelper().GetMultiDigraph(self.cmg_bp_policy)
            bp_policy_line_graph=MetagraphHelper().CreateLineGraph(digraph_bp_policy)

            log.info('generate canonical policies of MUD policy..')
            CanonicalPolicyHelper().GenerateCanonicalForm(digraph_original)
            canonical_policy1 = CanonicalPolicyHelper().canonical_policies

            flow_policies1=dict()
            for key in cmg_original_line_graph.node.keys():
                flow_policies1[key]=None
                # lookup the canonical policy of this flow
                flow1=None
                key_str='%s->%s'%(key[0],key[1])
                if key_str in canonical_policy1['final']:
                   flow1=canonical_policy1['final'][key_str]
                flow_policies1[key] = flow1

            log.info('generate canonical policies of SCADA best practice policy..')
            CanonicalPolicyHelper().GenerateCanonicalForm(digraph_bp_policy)
            canonical_policy2 = CanonicalPolicyHelper().canonical_policies

            flow_policies2=dict()
            for key in bp_policy_line_graph.node.keys():
                flow_policies2[key]=None
                # lookup the canonical policy of this flow
                flow1=None
                key_str='%s->%s'%(key[0],key[1])
                if key_str in canonical_policy2['final']:
                   flow1=canonical_policy2['final'][key_str]
                flow_policies2[key] = flow1

            log.info('check SCADA best practice compliance....')
            compliant = CanonicalPolicyHelper().CheckPolicyInclusion(flow_policies1,flow_policies2,cmg_original_line_graph,bp_policy_line_graph,
                                                            digraph_original,digraph_bp_policy,"MUD policy","SCADA best practice policy", False)
            if not compliant:
                log.warning('MUD policy is NOT best practice compliant')
            else:
                log.info('MUD policy is best practice compliant')

        except BaseException,e:
            log.error('check_bp_compliance:: %s'%(e))

    def get_semantic_difference(self, mud_file_path, target_zone):
        import json

        try:
            # read in MUD file
            file = mud_file_path
            default_mud_path=os.getcwd()
            if not isabs(mud_file_path): file = default_mud_path + '/' + mud_file_path

            extracted = None
            with open(file) as json_data:
                extracted = json.load(json_data)

            acl_details =  MetagraphHelper().get_device_acl_details(extracted,True)

            # create metagraphs
            vars02=[]
            props02=[]
            variables_set02=set()
            edge_list02 = self.get_edge_list(acl_details,vars02,props02,convert_ipaddresses_to_numeric=False)
            for var in vars02:
                variables_set02=variables_set02.union(var)
            propositions_set02=set(props02)
            cmg02 = ConditionalMetagraph(variables_set02,propositions_set02)
            cmg02.add_edges_from(edge_list02)

            # create metagraphs
            digraph_bp_policy = MetagraphHelper().GetMultiDigraph(self.cmg_bp_policy)

            lookup_map = dict()
            cmg02 = self.update_edges(cmg02,target_zone,lookup_map)
            digraph_original02 = MetagraphHelper().GetMultiDigraph(cmg02)
            self.PrintSemanticDifference(digraph_original02,digraph_bp_policy,"specified_policy","bp_policy",True,'Policy violations',cmg02,lookup_map)

        except BaseException,e:
            log.error('get_semantic_difference:: %s'%(e))

    def get_mud_policy_semantic_difference(self, mud_file_path1, mud_file_path2):
        import json

        try:
            # read in MUD files
            file1 = mud_file_path1
            default_mud_path=os.getcwd()
            if not isabs(mud_file_path1): file1 = default_mud_path + '/' + mud_file_path1

            file2 = mud_file_path2
            default_mud_path=os.getcwd()
            if not isabs(mud_file_path2): file2 = default_mud_path + '/' + mud_file_path2

            extracted1 = None
            with open(file1) as json_data:
                extracted1 = json.load(json_data)

            extracted2 = None
            with open(file2) as json_data:
                extracted2 = json.load(json_data)

            acl_details1 =  MetagraphHelper().get_device_acl_details(extracted1,False)
            acl_details2 =  MetagraphHelper().get_device_acl_details(extracted2,False)

            new_rule_count = len(acl_details1['from']) + len(acl_details1['to'])
            old_rule_count = len(acl_details2['from']) + len(acl_details2['to'])

            print('# MUD rules: new- %s, old- %s'%(new_rule_count, old_rule_count))

            # create metagraphs
            vars02=[]
            props02=[]
            variables_set02=set()
            edge_list02 = self.get_edge_list(acl_details1,vars02,props02,convert_ipaddresses_to_numeric=False)
            for var in vars02:
                variables_set02=variables_set02.union(var)
            propositions_set02=set(props02)
            cmg02 = ConditionalMetagraph(variables_set02,propositions_set02)
            cmg02.add_edges_from(edge_list02)

            vars03=[]
            props03=[]
            variables_set03=set()
            edge_list03 = self.get_edge_list(acl_details2,vars03,props03,convert_ipaddresses_to_numeric=False)
            for var in vars03:
                variables_set03=variables_set03.union(var)
            propositions_set03=set(props03)
            cmg03 = ConditionalMetagraph(variables_set03,propositions_set03)
            cmg03.add_edges_from(edge_list03)

            digraph_original02 = MetagraphHelper().GetMultiDigraph(cmg02)
            digraph_original03 = MetagraphHelper().GetMultiDigraph(cmg03)
            self.PrintSemanticDifference(digraph_original02,digraph_original03,"specified_policy","bp_policy",True,'Policy differences')

        except BaseException,e:
            log.error('get_semantic_difference:: %s'%(e))

    def PrintSemanticDifference(self, policy1, policy2, policy1_name,policy2_name,display_policy1_only,msg='policy differences::',original_policy1=None,lookup_map=None):
        from mgtoolkit.library import CanonicalPolicyHelper
        print('Get policy semantic difference..')
        count=1
        if policy1 and policy2:
            diff_lookup= CanonicalPolicyHelper().GetSemanticDifference(policy1,policy2)
            print(msg)
            #print('%s'%policy1_name)
            print('A-B::')
            if '1' in diff_lookup and diff_lookup['1'] and len(diff_lookup['1'])>0:
                for protocol, flows in diff_lookup['1'].iteritems():
                    for key, rules in flows.iteritems():
                        for rule in rules:
                             # get original rule TODO get this working
                            original = None # self.get_original_rule(rule, original_policy1, lookup_map)
                            if original is not None:
                                print(original)
                            else:
                                rule = rule.replace('icmp.type=[(1, 0)]','')
                                rule = rule.replace(';;','')
                                print('%s. %s'%(count,rule))
                                count+=1

            '''
            print('B-A::')
            if '2' in diff_lookup and diff_lookup['2'] and len(diff_lookup['2'])>0:
                for protocol, flows in diff_lookup['2'].iteritems():
                    for key, rules in flows.iteritems():
                        for rule in rules:
                             # get original rule TODO get this working
                            original = None # self.get_original_rule(rule, original_policy1, lookup_map)
                            if original is not None:
                                print(original)
                            else:
                                rule = rule.replace('icmp.type=[(1, 0)]','')
                                rule = rule.replace(';;','')
                                print(rule)'''

            print('-----------------')

    def update_edges(self, cmg02, target_zone,lookup_map):
        from mgtoolkit.library import CanonicalPolicyHelper
        from mgtoolkit.exception import InvalidTargetZoneException
        from mgtoolkit.properties import resources
        vars = []
        props = []
        new_edges = []
        for edge in cmg02.edges:
            inv = set()
            outv = set()
            props += list(edge.attributes)
            invertex = edge.invertex.difference(edge.attributes)
            outvertex = edge.outvertex
            for elt in list(invertex):
                if elt=='device':
                   inv = inv.union({target_zone})
                   lookup_map[target_zone]=['device']
                elif CanonicalPolicyHelper().is_private_ipaddress(elt):
                    if target_zone=='dmz':
                        # pick next least secure internal zone relative to dmz
                        inv = inv.union({'corporate_zone'})
                        if 'corporate_zone' not in lookup_map:
                            lookup_map['corporate_zone']=[]
                        if elt not in lookup_map['corporate_zone']:
                            lookup_map['corporate_zone'].append(elt)
                    else:
                        # least secure internal zone
                        inv = inv.union({'dmz'})
                        if 'dmz' not in lookup_map:
                            lookup_map['dmz']=[]
                        if elt not in lookup_map['dmz']:
                            lookup_map['dmz'].append(elt)
                else:
                   if target_zone=='internet_zone':
                       # error
                       raise InvalidTargetZoneException(resources['specified_target_zone_invalid'])
                   else:
                       inv = inv.union({'internet_zone'})
                       if 'internet_zone' not in lookup_map:
                            lookup_map['internet_zone']=[]
                       if elt not in lookup_map['internet_zone']:
                            lookup_map['internet_zone'].append(elt)

            for elt in list(outvertex):
                if elt=='device':
                   outv = outv.union({target_zone})
                   lookup_map[target_zone] = ['device']

                elif CanonicalPolicyHelper().is_private_ipaddress(elt):
                   if target_zone=='dmz':
                      # pick next least secure internal zone relative to dmz
                      outv = outv.union({'corporate_zone'})
                      if 'corporate_zone' not in lookup_map:
                          lookup_map['corporate_zone']=[]
                      if elt not in lookup_map['corporate_zone']:
                          lookup_map['corporate_zone'].append(elt)
                   else:
                      # least secure internal zone
                      outv = outv.union({'dmz'})
                      if 'dmz' not in lookup_map:
                          lookup_map['dmz']=[]
                      if elt not in lookup_map['dmz']:
                          lookup_map['dmz'].append(elt)
                else:
                   outv = outv.union({'internet_zone'})
                   if 'internet_zone' not in lookup_map:
                      lookup_map['internet_zone']=[]
                   if elt not in lookup_map['internet_zone']:
                      lookup_map['internet_zone'].append(elt)

            vars += list(inv)
            vars += list(outv)
            new_edges.append(Edge(inv,outv, attributes=edge.attributes, label=edge.label))

        cmg = ConditionalMetagraph(set(vars),set(props))
        cmg.add_edges_from(new_edges)
        return cmg

    def get_edge_list(self,acl_details,variables_set,propositions_set,convert_ipaddresses_to_numeric=False):
        edge_list=[]
        id=0
        import socket
        for direction, acls in acl_details.iteritems():
            for acl in acls:
                if direction=='from':
                    try:
                        invertex = set([acl.source])
                        if convert_ipaddresses_to_numeric:
                            dest=list(acl.dest)[0]
                            if self.is_domain_name(dest):
                               ipaddress = '%s/32'%socket.gethostbyname(dest.strip())
                               outvertex = set(MetagraphHelper().get_ipaddresses_numeric(set([ipaddress])))
                            else:
                               outvertex = set(MetagraphHelper().get_ipaddresses_numeric(set(acl.dest)))
                        else:
                            outvertex = set(acl.dest)
                    except:
                        continue

                elif direction=='to':
                    try:
                        outvertex = set([acl.dest])
                        if convert_ipaddresses_to_numeric:
                            source=list(acl.source)[0]
                            if self.is_domain_name(source):
                               ipaddress = '%s/32'%socket.gethostbyname(source.strip())
                               invertex = set(MetagraphHelper().get_ipaddresses_numeric(set([ipaddress])))
                            else:
                               invertex = set(MetagraphHelper().get_ipaddresses_numeric(set(acl.source)))
                        else:
                            invertex = set(acl.source)
                    except:
                        continue

                attributes = []
                attributes.append('protocol=%s'%acl.protocol)
                dports = MetagraphHelper().get_port_descriptor(acl.protocol, acl.dports, 'dport')
                sports = MetagraphHelper().get_port_descriptor(acl.protocol, acl.sports, 'sport')
                if dports is not None:
                    attributes.append(dports)
                if sports is not None:
                    attributes.append(sports)
                attributes.append('action=%s'%acl.action)
                # tag edge id
                edge_id = 'edge%s'%id
                #attributes.append('original_id=%s'%edge_id)

                if list(attributes) not in propositions_set:
                    propositions_set +=list(attributes)
                    #propositions_set = propositions_set.union(attributes)

                if invertex not in variables_set:
                    variables_set.append(invertex)
                if outvertex not in variables_set:
                    variables_set.append(outvertex)

                #variables_set = variables_set.union(invertex)
                #variables_set = variables_set.union(outvertex)
                edge = Edge(invertex,outvertex,attributes,label=edge_id)
                edge_list.append(edge)
                id+=1

        return edge_list

    def get_duplicate_edges(self, edge_list):
        temp = []
        duplicates=[]
        for edge in edge_list:
            if edge in temp and edge not in duplicates:
                duplicates.append(edge)
            else:
                temp.append(edge)

        return duplicates

    def print_edge(self, edge):
        try:
            source = edge.invertex.difference(edge.attributes)
            dest = edge.outvertex
            protocol = self.get_protocols(edge.attributes)
            action = self.get_actions(edge.attributes)
            dports = self.get_tcp_ports(edge.attributes,True)
            if dports is None or len(dports)==0:
                dports = self.get_udp_ports(edge.attributes, True)

            sports = self.get_tcp_ports(edge.attributes, False)
            if sports is None or len(sports)==0:
                sports = self.get_udp_ports(edge.attributes, False)


            log.info('policy:: source=%s, dest=%s, protocol=%s, sport=%s, dport=%s, action=%s'%
                  (source, dest, protocol, sports, dports, action))

        except BaseException, e:
            log.error('print_edge: %s'%str(e))

    def read_file(self, file):
        with open(file, 'r') as f:
            data = [row for row in csv.reader(f.read().splitlines())]
        return data

    def extract_ipaddresses(self, ipaddr_str):
        result = []
        if ipaddr_str is not None:
           ipaddr_str = ipaddr_str.replace('[','')
           ipaddr_str = ipaddr_str.replace(']','')
           result = ipaddr_str.split('|')

        return result

    def is_domain_name(self,names):
        import socket
        try:
            items = names.split(',')
            for name in items:
                # TODO: remove public addresses altogether
                socket.gethostbyname(name.strip())
            return True
        except socket.gaierror:
            pass

        return False

    def __init__(self):
        self.output_path=None
        self.local_gateway_ipaddr = "192.168.1.1"
        self.manufacturers= ['lifx','samsung', 'amazon', 'august', 'awair', 'belkin', 'carematix', 'canary',
                        'google', 'dropcam', 'toytalk', 'hp', 'hue', 'phillips', 'evrythng', 'nest',
                        'netatmo', 'pix-star', 'ring', 'smartthing', 'tplink', 'invoxia', 'xbcs', 'withings']

        # BP policy
        # SCADA bp policy
        variables_set2={'corporate_zone','scada_zone','abstract_zone','internet_zone','management_zone', 'carrier_zone', 'firewall_zone', 'dmz'}
        edge_list2=[]
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=21', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=20', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=25', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=23', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=22', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=88', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=135', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=636', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=992', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=554', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=444', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=139', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=445', 'action=accept']))

        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=17', 'UDP.dport=67', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=17', 'UDP.dport=68', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=17', 'UDP.dport=636', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=17', 'UDP.dport=520', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=17', 'UDP.dport=521', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=17', 'UDP.dport=53', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=17', 'UDP.dport=123', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=17', 'UDP.dport=161', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=17', 'UDP.dport=137', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=17', 'UDP.sport=53', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=17', 'UDP.sport=123', 'action=accept']))

        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=80', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=443', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=631', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=17', 'UDP.dport=1024-65535','UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'dmz'},attributes=['protocol=1', 'action=accept']))

        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=6', 'TCP.dport=21', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=6', 'TCP.dport=20', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=6', 'TCP.dport=25', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=6', 'TCP.dport=23', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=6', 'TCP.dport=22', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=6', 'TCP.dport=88', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=6', 'TCP.dport=135', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=6', 'TCP.dport=80', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=6', 'TCP.dport=443', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=6', 'TCP.dport=631', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=17', 'UDP.dport=53', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=17', 'UDP.dport=123', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=1', 'action=accept']))

        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=17', 'UDP.sport=67', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=17', 'UDP.sport=68', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=17', 'UDP.sport=636', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=17', 'UDP.sport=520', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=17', 'UDP.sport=521', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=17', 'UDP.sport=53', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=17', 'UDP.sport=123', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=17', 'UDP.sport=161', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=17', 'UDP.sport=137', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'corporate_zone'},attributes=['protocol=17', 'UDP.sport=1024-65535', 'action=accept'])) #3179

        edge_list2.append(Edge({'scada_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=992', 'action=accept']))
        edge_list2.append(Edge({'scada_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=88', 'action=accept']))
        edge_list2.append(Edge({'scada_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=636', 'action=accept']))
        edge_list2.append(Edge({'scada_zone'},{'dmz'},attributes=['protocol=17', 'UDP.dport=636', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'scada_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=23', 'action=accept']))
        edge_list2.append(Edge({'scada_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=21', 'action=accept']))
        edge_list2.append(Edge({'scada_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=20', 'action=accept']))
        edge_list2.append(Edge({'scada_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=25', 'action=accept']))
        edge_list2.append(Edge({'scada_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=502', 'action=accept']))
        edge_list2.append(Edge({'scada_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=135', 'action=accept']))
        edge_list2.append(Edge({'scada_zone'},{'dmz'},attributes=['protocol=1', 'action=accept']))
        edge_list2.append(Edge({'scada_zone'},{'dmz'},attributes=['protocol=17', 'UDP.sport=636', 'action=accept']))

        edge_list2.append(Edge({'dmz'},{'scada_zone'},attributes=['protocol=6', 'TCP.dport=22', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'scada_zone'},attributes=['protocol=6', 'TCP.dport=443', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'scada_zone'},attributes=['protocol=6', 'TCP.dport=992', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'scada_zone'},attributes=['protocol=6', 'TCP.dport=88', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'scada_zone'},attributes=['protocol=6', 'TCP.dport=636', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'scada_zone'},attributes=['protocol=17', 'UDP.dport=636', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'scada_zone'},attributes=['protocol=1', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'scada_zone'},attributes=['protocol=17', 'UDP.sport=636', 'action=accept']))

        edge_list2.append(Edge({'corporate_zone'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=445', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=135', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=80', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=443', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=631', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=21', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=20', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=25', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=23', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=22', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'internet_zone'},attributes=['protocol=17', 'UDP.dport=123', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'internet_zone'},attributes=['protocol=17', 'UDP.dport=53', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'internet_zone'},attributes=['protocol=17', 'UDP.dport=161', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'internet_zone'},attributes=['protocol=17', 'UDP.dport=1024-65535', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'corporate_zone'},{'internet_zone'},attributes=['protocol=1', 'action=accept']))

        edge_list2.append(Edge({'internet_zone'},{'corporate_zone'},attributes=['protocol=6', 'TCP.dport=80', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'corporate_zone'},attributes=['protocol=6', 'TCP.dport=443', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'corporate_zone'},attributes=['protocol=6', 'TCP.dport=631', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'corporate_zone'},attributes=['protocol=6', 'TCP.dport=22', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'corporate_zone'},attributes=['protocol=17', 'UDP.sport=123', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'corporate_zone'},attributes=['protocol=17', 'UDP.sport=53', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'corporate_zone'},attributes=['protocol=17', 'UDP.sport=161', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'corporate_zone'},attributes=['protocol=17', 'UDP.sport=1024-65535', 'action=accept']))


        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=445', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=135', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=80', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=443', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=631', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=21', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=20', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=25', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=23', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=22', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=17', 'UDP.dport=123', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=17', 'UDP.dport=53', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=17', 'UDP.dport=161', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=17', 'UDP.dport=1024-65535', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=1', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=17', 'UDP.sport=123', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=17', 'UDP.sport=53', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=17', 'UDP.sport=161', 'action=accept']))
        edge_list2.append(Edge({'dmz'},{'internet_zone'},attributes=['protocol=6', 'TCP.dport=465', 'action=accept']))

        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=445', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=135', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=80', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=443', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=631', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=21', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=20', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=25', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=23', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=22', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=17', 'UDP.dport=123', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=17', 'UDP.dport=53', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=17', 'UDP.dport=161', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=6', 'TCP.dport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=17', 'UDP.dport=1024-65535', 'UDP.sport=1024-65535', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=1', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=17', 'UDP.sport=123', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=17', 'UDP.sport=53', 'action=accept']))
        edge_list2.append(Edge({'internet_zone'},{'dmz'},attributes=['protocol=17', 'UDP.sport=161', 'action=accept']))

        propositions_set2=set()
        for edge in edge_list2:
            propositions_set2 = propositions_set2.union(set(edge.attributes))

        self.cmg_bp_policy = ConditionalMetagraph(variables_set2,propositions_set2)
        self.cmg_bp_policy.add_edges_from(edge_list2)









