#!/usr/bin/env python2

import socket
import xml.etree.ElementTree as ET
import re
from scapy.all import *
# from scapy.layers.http import *
from scapy.layers.http import HTTPRequest 
from datetime import datetime
import os


# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# s = socket.socket(socket.AF_LOCAL, socket.SOCK_RAW)

topics = {}

#ID and port of nodes who have asked this info
sys_state = {}
topic_type = {}
lookup_node = {}




# counter = 0

def packet_callback(packet):
    global topics
    if packet[TCP].payload:
        if packet[IP].dport == 11311:
            load = str(bytes(packet[TCP].payload))
            if "<?xml version=\'1.0\'?>" in load:
                # packet.show()
                # print(packet[IP].sport)
                # print(load)
                xml = re.search('<\?xml version=\'1.0\'\?>[\s\S]*?<\/methodCall>', load).group(0)
                root = ET.fromstring(xml)
                if root[0].text == "registerPublisher":
                    key = root[1][1][0][0].text
                    if not(key in topics.keys()):
                        topics[key] = packet[IP].sport

                if root[0].text == "getSystemState":
                    key = packet[IP].sport
                    if not(key in sys_state.keys()):
                        sys_state[key] = root[1][0][0][0].text 

                if root[0].text == "getTopicTypes":
                    key = packet[IP].sport
                    if not(key in topic_type.keys()):
                        topic_type[key] = root[1][0][0][0].text  

                if root[0].text == "lookupNode":
                    key = packet[IP].sport
                    if not(key in lookup_node.keys()):
                        lookup_node[key] = root[1][0][0][0].text 
                
                if root[0].text == "unregisterPublisher":
                    key = root[1][1][0][0].text
                    if key in topics.keys():
                        tmp = topics[key]
                        if tmp == packet[IP].sport:
                            # print("No issues here")
                            del topics[key]
                        else:
                            PID_list = []
                            port = packet[IP].sport
                            o_port = port - 2
                            port_list = [port, o_port]
                            if (o_port in sys_state.keys()) and (o_port in topic_type.keys()) and (o_port in lookup_node.keys()):
                                # if node name (value for this key) is same across dictionaries 
                                stream = os.popen('fuser ' + str(o_port) + '/tcp')
                                output = stream.read()
                                if output == '':
                                    PID = 'UNKNOWN'
                                else:
                                    PID = output
                                    PID_list.append(PID)
                                node_name = sys_state[o_port]

                            stream2 = os.popen('fuser ' + str(port) + '/tcp')
                            output2 = stream2.read()
                            if output2 == '':
                                PID2 = 'UNKNOWN'
                            else:
                                PID2 = output2
                                PID_list.append(PID2)
                            
                            if not PID_list:
                                PID_list = "UNKNOWN"
                        
                            now = datetime.now()
                            current_time = now.strftime("%H:%M:%S")

                            print("Unusual Activity Detected:")
                            print("    Action: UnregisterPublisher")
                            print("    Target topic: " + key)
                            print("    Time: " + current_time)
                            print("    Malicious node: " + node_name)
                            print("    Related ports: " + str(port_list))
                            print("    Related PIDs: " + str(PID_list))


                            #restore state of topic
                            del topics[key]


                if "<string>unregisterPublisher</string>" in load:
                    if len(root[1][0][0][0][0]) != 0:
                        for element in root[1][0][0][0][0]:
                            if element[0][1][1][0].text == "unregisterPublisher":
                                key = element[0][0][1][0][0][1][0].text
                                if key in topics.keys():
                                    tmp = topics[key]
                                    if tmp == packet[IP].sport:
                                        # print("No issues here")
                                        del topics[key]
                                    else:
                                        now = datetime.now()
                                        current_time = now.strftime("%H:%M:%S")
                                        print("Unusual UnregisterPublisher detected on topic: " + key + "at " + current_time)
                                        # del topics[key]


sniff(filter='tcp', iface="lo", prn=packet_callback, store=0, count=0)