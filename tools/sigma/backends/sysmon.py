import re
import sigma
from sigma.backends.base import SingleTextQueryBackend
from sigma.backends.mixins import MultiRuleOutputMixin
from sigma.parser.condition import ConditionOR, ConditionAND, NodeSubexpression, SigmaAggregationParser, SigmaConditionParser, SigmaConditionTokenizer, dumpNode, ConditionNOT
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from yaml.nodes import Node


from .exceptions import NotSupportedError

#python tools/sigmac $RULE -t sysmon -c sysmon -d

class SysmonConfigBackend(SingleTextQueryBackend, MultiRuleOutputMixin):
    """Converts Sigma rule into sysmon XML configuration"""
    identifier = "sysmon"
    active = True
    config_required = True


    def __init__(self, *args, **kwargs):
        self.table = None
        self.logsource = None
        self.allowedSource = {
            "process_creation": "ProcessCreate",
            "file_change":"FileCreateTime",
            "network_connection":"NetworkConnect",
            "process_termination":"ProcessTerminate",
            "driver_load":"DriverLoad",
            "image_load":"ImageLoad",
            "create_remote_thread":"CreateRemoteThread",
            "raw_access_thread":"RawAccessRead",
            "process_access":"ProcessAccess",
            "file_event":"FileCreate",
            "registry_event":"RegistryEvent",
            "create_stream_hash":"FileCreateStreamHash",
            "pipe_created":"PipeEvent",
            "wmi_event":"WmiEvent",
            "dns_query":"DnsQuery",
            "process_tampering":"ProcessTampering"
        }

        self.eventidTagMapping = {
            1: "ProcessCreate",
            2: "FileCreateTime",
            3: "NetworkConnect",
            5: "ProcessTerminate",
            6: "DriverLoad",
            7: "ImageLoad",
            8: "CreateRemoteThread",
            9: "RawAccessRead",
            10: "ProcessAccess",
            11: "FileCreate",
            12: "RegistryEvent",
            13: "RegistryEvent",
            14: "RegistryEvent",
            15: "FileCreateStreamHash",
            17: "PipeEvent",
            18: "PipeEvent",
            19: "WmiEvent",
            20: "WmiEvent",
            21: "WmiEvent",
            22: "DNSQuery",
            257: "DNSQuery",
            23: "FileDelete"
        }
        
        self.rules = []
        self.event_id = []
        return super().__init__(*args, **kwargs)

    def traverse_tree(self,node,indent=''):
        if hasattr(node, 'items'):
            #if current node is ConditionNot then return
            # print("%s%s<%s>" % (indent, type(node).__name__,
            #                     type(node.items).__name__))
            if type(node) == ConditionNOT:
                return
            if type(node) == ConditionAND:
                if type(node.items) == list:
                    self.extract_include_and_rules(node.items)
            if type(node) == ConditionOR:
                if type(node.items) == list:
                    self.extract_include_or_rules(node.items)
                    pass

            if type(node.items) != list:
                self.traverse_tree(node.items, indent + '  ')
            else:
                for item in node.items:
                    self.traverse_tree(item, indent + '  ')
        else:
            # self.extract_include_rules(node)
            pass
            # print("%s%s=%s" % (indent, type(node).__name__,
            #                         repr(node)))
        return ''

    def dumpNode(node, indent=''):   # pragma: no cover
        """
        Recursively print the AST rooted at *node* for debugging.
        """
        if hasattr(node, 'items'):
            print("%s%s<%s>" % (indent, type(node).__name__,
                                type(node.items).__name__))
            if type(node.items) != list:
                dumpNode(node.items, indent + '  ')
            else:
                for item in node.items:
                    dumpNode(item, indent + '  ')
        else:
            print("%s%s=%s" % (indent, type(node).__name__,
                                    repr(node)))
        return node 

    def extract_include_or_rules(self,node):
        sub_expression = dict()
        # if list, it's an AND
        if isinstance(node,list):
            for item in node:
                if type(item)==tuple:
                    field = item[0]
                    values = item[1]
                    #Change values to a list to iterate over
                    #If value is None, skip current iteration
                    if values == None:
                        continue
                    if not isinstance(item[1],list):
                        values = [item[1]]

                    if field == 'EventID':
                        self.event_id = values
                    else:
                        if not isinstance(item[1],list):
                            values = [item[1]]

                        #Add in modifiers to fields and values
                        contains = re.compile('^\*.*\*$')
                        starts_with = re.compile('.*\*$')
                        ends_with = re.compile('\*.*$')
                        # ampersand = re.compile('&')

                        modified_values = []

                        #Check if contains or ends with modifier is present
                        for value in values:
                            if isinstance(value,SigmaRegularExpressionModifier):
                                return

                            #escape ampersand character in xml
                            if type(value) is str:
                                value = value.replace('&','&amp;')
                            if contains.match(str(value)) or starts_with.match(str(value)):
                                modified_field = field+'|contains'
                                modified_values.append(value.replace('*',''))
                                pass
                            elif ends_with.match(str(value)):
                                modified_field = field+'|end with'
                                modified_values.append(value.replace('*',''))
                                pass
                            else:
                                modified_field = field+'|is'
                                modified_values.append(value)
                                pass

                        #Check if it is contains all. If contains all is present, override previous modifier
                        del_keys = []
                        for key, value in sub_expression.items():
                            if field.split("|")[0] == key.split("|")[0]:
                                modified_field = field.split("|")[0]+'|contains any'
                                modified_values = modified_values + value
                                del_keys.append(key)
                        
                        #Delete keys that were aggregated by contains all
                        if del_keys:
                            for del_key in del_keys:
                                del sub_expression[del_key]

                        sub_expression[modified_field] = modified_values
                        # print('modified_field',modified_field)
                        # print('returned_values',modified_values)
                        # print('sub expression',sub_expression)

            if sub_expression:
                # print('sub_expression',sub_expression)
                self.rules.append(sub_expression)
            
    def extract_include_and_rules(self,node):

        sub_expression = dict()

        # if list, it's an AND
        if isinstance(node,list):
            for item in node:
                if type(item)==tuple:
                    field = item[0]
                    values = item[1]
                    #If value is None, skip current iteration
                    if values == None:
                        continue
                    #Change values to a list to iterate over
                    if not isinstance(item[1],list):
                        values = [item[1]]

                    if field == 'EventID':
                        self.event_id = values
                    else:
                        #Add in modifiers to fields and values
                        contains = re.compile('^\*.*\*$')
                        starts_with = re.compile('.*\*$')
                        ends_with = re.compile('\*.*$')

                        modified_values = []

                        #Check if contains or ends with modifier is present
                        for value in values:
                            if isinstance(value,SigmaRegularExpressionModifier):
                                return

                            #escape ampersand character in xml
                            if type(value) is str:
                                value = value.replace('&','&amp;')
                            if contains.match(str(value)) or starts_with.match(str(value)):
                                modified_field = field+'|contains'
                                modified_values.append(value.replace('*',''))
                                pass
                            elif ends_with.match(str(value)):
                                modified_field = field+'|end with'
                                modified_values.append(value.replace('*',''))
                                pass
                            else:
                                modified_field = field+'|is'
                                modified_values.append(value)
                                pass

                        #Check if it is contains all. If contains all is present, override previous modifier
                        del_keys = []
                        for key, value in sub_expression.items():
                            if field.split("|")[0] == key.split("|")[0]:
                                modified_field = field.split("|")[0]+'|contains all'
                                modified_values = modified_values + value
                                del_keys.append(key)
                        
                        #Delete keys that were aggregated by contains all
                        if del_keys:
                            for del_key in del_keys:
                                del sub_expression[del_key]

                        #Only for and conditions. If subexpression has ends with as a list of more than one, change modifier to contains any
                        if modified_field.split("|")[1] == 'end with' and len(modified_values)>1:
                            modified_field = field.split("|")[0]+'|contains any'

                        sub_expression[modified_field] = modified_values
                        # print('modified_field',modified_field)
                        # print('returned_values',modified_values)
                        # print('sub expression',sub_expression)

            if sub_expression:
                self.rules.append(sub_expression)

    def generate_sysmon_rules(self):
        output = ''
        #map event ID
        event_id_tags = set()
        #Some rules will have multiple event ids
        #Iterate through event ids
        for event_id in self.event_id:
            #if event_id is not specified, return
            if not self.eventidTagMapping.get(event_id):
                return
            event_id_tag = self.eventidTagMapping.get(event_id)
            #store event_id_tag in tuple
            event_id_tags.add(event_id_tag)

        for event_id in event_id_tags:
            
            header = f'<Sysmon schemaversion="4.30">\n\t<EventFiltering>\n\t\t<RuleGroup name="" groupRelation="or">\n\t\t\t<{event_id} onmatch="include">\n'

            footer = f'\t\t\t</{event_id}>\n\t\t</RuleGroup>\n\t</EventFiltering>\n</Sysmon>'

            # print(header)
            output += header

            #Iterate through rules
            for rule in self.rules:
                if len(rule) > 1:
                    output += '\t\t\t\t\t<Rule name="" groupRelation="and">\n'
                    # print('\t\t\t\t\t<RuleGroup name="" groupRelation="and">')
                    for field,values in rule.items():
                        field_name = field.split('|')[0]
                        field_modifier = field.split('|')[1]
                        if field_modifier == "contains all" or field_modifier == "contains any":
                            values = ';'.join(values)
                            output += f'\t\t\t\t\t\t<{field_name} condition="{field_modifier}">{values}</{field_name}>\n'
                            # print('\t\t\t\t\t\t',f'<{field_name} condition="{field_modifier}">',values,f'</{field_name}>')
                        else:
                            for value in values:
                                output += f'\t\t\t\t\t\t<{field_name} condition="{field_modifier}">{value}</{field_name}>\n'
                                # print('\t\t\t\t\t\t',f'<{field_name} condition="{field_modifier}">',value,f'</{field_name}>')
                    output += '\t\t\t\t\t</Rule>\n'
                    # print('\t\t\t\t\t</RuleGroup>')
                else:
                    for field,values in rule.items():
                        field_name = field.split('|')[0]
                        field_modifier = field.split('|')[1]
                        if field_modifier == "contains all" or field_modifier == "contains any":
                            values = ';'.join(values)
                            output += f'\t\t\t\t\t<{field_name} condition="{field_modifier}">{values}</{field_name}>\n'
                            # print(f'\t\t\t\t\t<{field_name} condition="{field_modifier}">',values,f'</{field_name}>')
                        else:
                            for value in values:
                                output += f'\t\t\t\t\t<{field_name} condition="{field_modifier}">{value}</{field_name}>\n'
                                # print(f'\t\t\t\t\t<{field_name} condition="{field_modifier}">',value,f'</{field_name}>')
            pass
            output += footer
            self.rules = []
            return output

    def generate(self, sigmaparser):
        for element in sigmaparser.condparsed:
            self.traverse_tree(element.parsedSearch)
        sysmon_config = self.generate_sysmon_rules()
        
        if sysmon_config:
            return sysmon_config