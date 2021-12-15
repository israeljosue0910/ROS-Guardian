#!/usr/bin/env python

import socket
import xml.etree.ElementTree as ET
import re
from scapy.all import *
# from scapy.layers.http import *
from scapy.layers.http import HTTPRequest 
from datetime import datetime
import os
from os.path import exists

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
wifi = s.getsockname()[0]
host_name = socket.gethostname()

# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# s = socket.socket(socket.AF_LOCAL, socket.SOCK_RAW)

topics = {}

#ID and port of nodes who have asked this info
sys_state = {}
topic_type = {}
lookup_node = {}
lookup_service = {}
node = {}
param_names = {}
pub_update = {}
toggle = True
toggle2 = True
toggle3 = True
toggle4 = True

# counter = 0

file1 = open("ROS-Guardian_log.txt", "w")  # append mode
file1.close()

def get_key(val, dict):
    for key, value in dict.items():
         if val == value:
             return key
 
    return "key doesn't exist"

def unusual_actvt(packet, key, root, n_name):
    global topics, sys_state, topic_type, lookup_node, lookup_service, node

    PID_list = []
    port = packet[IP].sport
    # o_port = port - 2
    attack = False
    num_port = node.get(n_name)

    for i in range(2, num_port + 2, 2):
        o_port = port - i

        if key[1] == "sub" or key[1] == "pub":
            if (o_port in sys_state.keys()) and (o_port in topic_type.keys()) and (o_port in lookup_node.keys()):
                if ((sys_state.get(o_port) == topic_type.get(o_port)) and (sys_state.get(o_port) == lookup_node.get(o_port))):
                    attack = True
                    break
            elif (o_port in lookup_node.keys()) and (o_port in sys_state.keys()):
                if ((lookup_node.get(o_port) == sys_state.get(o_port))):
                    attack = True
                    break
        elif key[1] == "serv":
            if (o_port in sys_state.keys()) and (o_port in lookup_service.keys()):
                if ((sys_state.get(o_port) == lookup_service.get(o_port))):
                    attack = True
                    break
            elif (o_port in lookup_node.keys()) and (o_port in sys_state.keys()):
                if ((lookup_node.get(o_port) == sys_state.get(o_port))):
                    attack = True
                    break
    
    if attack:
        port_list = [port, o_port]

        for p in port_list:
            stream = os.popen('fuser ' + str(p) + '/tcp')
            output = stream.read()
            if output == '':
                pass
            else:
                PID = output
                PID_list.append(PID)
        if not PID_list:
            PID_list = "UNKNOWN"
        else:
            for p in port_list:
                stream = os.popen('fuser -k' + str(p) + '/tcp')
                output = stream.read()
                print(output)

        node_name = sys_state[o_port]

        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")

        l1 = "Unusual Activity Detected:" + "\n"
        l2 = "    Action: " + str(root[0].text) + "\n"
        l3 = "    Target: " + key[0] + "\n"
        l4 = "    Victim node: " + n_name + "\n"
        l5 = "    Time: " + current_time + "\n"
        l6 = "    Malicious node: " + node_name + "\n"
        l7 = "    Related ports: " + str(port_list) + "\n"
        l8 = "    Related PIDs: " + str(PID_list) + "\n"
        print(l1 + l2 + l3 + l4 + l5 + l6 + l7 + l8)
        file1 = open("ROS-Guardian_log.txt", "a")
        L = [l1, l2, l3, l4, l5, l6, l7, l8]
        file1.writelines(L)
        file1.close()

def packet_callback(packet):
    global topics, file1, toggle, toggle2, toggle3, toggle4
    if packet[TCP].payload:
        load = str(bytes(packet[TCP].payload))
        # print(load)
        if packet[IP].dport == 11311:
            # load = str(bytes(packet[TCP].payload))
            if ("<?xml version=\'1.0\'?>" in load) or ("<?xml version=\"1.0\"?>" in load):
                # packet.show()
                # print(packet[IP].sport)
                # print(load)
                try:
                    xml = re.search('<\?xml version=\'1.0\'\?>[\s\S]*?<\/methodCall>', load).group(0)
                except:
                    xml = re.search('<\?xml version=\"1.0\"\?>[\s\S]*?<\/methodCall>', load).group(0)
                root = ET.fromstring(xml)
                if root[0].text == "registerPublisher":
                    key = (root[1][1][0][0].text, "pub")
                    node_name = root[1][0][0][0].text
                    if not(key in topics.keys()):
                        topics[key] = packet[IP].sport
                    if not(node_name in node.keys()):
                        node[node_name] = 1
                    else:
                        tmp = node.get(node_name)
                        node[node_name] = tmp + 1
                
                if root[0].text == "registerSubscriber":
                    key = (root[1][1][0][0].text, "sub")
                    node_name = root[1][0][0][0].text
                    if not(key in topics.keys()):
                        topics[key] = packet[IP].sport
                    if not(node_name in node.keys()):
                        node[node_name] = 1
                    else:
                        tmp = node.get(node_name)
                        node[node_name] = tmp + 1

                if root[0].text == "registerService":
                    key = (root[1][1][0][0].text, "serv")
                    node_name = root[1][0][0][0].text
                    if not(key in topics.keys()):
                        topics[key] = packet[IP].sport
                    if not(node_name in node.keys()):
                        node[node_name] = 1
                    else:
                        tmp = node.get(node_name)
                        node[node_name] = tmp + 1
                
                if root[0].text == "getSystemState":
                    key = packet[IP].sport
                    if not(key in sys_state.keys()):
                        sys_state[key] = root[1][0][0][0].text 

                if root[0].text == "getParamNames":
                    key = packet[IP].sport
                    if not(key in sys_state.keys()):
                        param_names[key] = root[1][0][0][0].text 

                if root[0].text == "getTopicTypes":
                    key = packet[IP].sport
                    if not(key in topic_type.keys()):
                        topic_type[key] = root[1][0][0][0].text  

                if root[0].text == "lookupNode":
                    key = packet[IP].sport
                    if not(key in lookup_node.keys()):
                        lookup_node[key] = root[1][0][0][0].text 
                    
                if root[0].text == "lookupService":
                    key = packet[IP].sport
                    if not(key in lookup_node.keys()):
                        lookup_service[key] = root[1][0][0][0].text 
                
                if root[0].text == "unregisterPublisher":
                    key = (root[1][1][0][0].text, "pub")
                    node_name = root[1][0][0][0].text
                    if key in topics.keys():
                        tmp = topics[key]
                        if tmp == packet[IP].sport:
                            # print("No issues here")
                            del topics[key]
                        else:
                            unusual_actvt(packet, key, root, node_name)
                            #restore state of topic
                            del topics[key]

                if root[0].text == "unregisterService":
                    key = (root[1][1][0][0].text, "serv")
                    node_name = root[1][0][0][0].text
                    if key in topics.keys():
                        tmp = topics[key]
                        if tmp == packet[IP].sport:
                            # print("No issues here")
                            del topics[key]
                        else:
                            unusual_actvt(packet, key, root, node_name)
                            #restore state of topic
                            del topics[key]

                if root[0].text == "unregisterSubscriber":
                    key = (root[1][1][0][0].text, "sub")
                    node_name = root[1][0][0][0].text
                    if key in topics.keys():
                        tmp = topics[key]
                        if tmp == packet[IP].sport:
                            # print("No issues here")
                            del topics[key]
                        else:
                            unusual_actvt(packet, key, root, node_name)
                            #restore state of topic
                            del topics[key]

                            # stream2 = os.popen('fuser ' + str(port) + '/tcp')
                            # output2 = stream2.read()
                            # if output2 == '':
                            #     PID2 = 'UNKNOWN'
                            # else:
                            #     PID2 = output2
                            #     PID_list.append(PID2)

                if root[0].text == "setParam":
                    param1 = root[1][0][0][0].text
                    param2 = root[1][1][0][0].text
                    if "rosparam" in param1 and param2 == "/":
                        if toggle2:
                            file1 = open("ROS-Guardian_log.txt", "a")
                            l1 = "Parameter server has been wiped \n"
                            L = [l1]
                            file1.writelines(L)
                            file1.close()
                            print(l1)
                            toggle2 = False
                        else:
                            toggle2 = True
                
                if root[0].text == "unsubscribeParam":
                    port = packet[IP].sport
                    port_2 = port - 2
                    port_4 = port - 4
                    PID_list = []
                    if (port_4 in param_names.keys()) and (port_4 in lookup_node.keys()) and (port_2 in sys_state.keys()):
                        if (param_names.get(port_4) == (lookup_node.get(port_4))):
                            if toggle3:
                                port_list = [port_4, port_2, port]
                                for p in port_list:
                                    stream = os.popen('fuser ' + str(p) + '/tcp')
                                    output = stream.read()
                                    if output == '':
                                        pass
                                    else:
                                        PID = output
                                        PID_list.append(PID)
                                if not PID_list:
                                    PID_list = "UNKNOWN"
                                else:
                                    for p in port_list:
                                        stream = os.popen('fuser -k' + str(p) + '/tcp')
                                        output = stream.read()
                                        print(output)
                                    
                                node_name = param_names[port_4]

                                now = datetime.now()
                                current_time = now.strftime("%H:%M:%S")
                                n_name = root[1][0][0][0].text
                                target_param = root[1][2][0][0].text

                                l1 = "Unusual Activity Detected:" + "\n"
                                l2 = "    Action: " + str(root[0].text) + "\n"
                                l3 = "    Target: " + target_param + "\n"
                                l4 = "    Victim node: " + n_name + "\n"
                                l5 = "    Time: " + current_time + "\n"
                                l6 = "    Malicious node: " + node_name + "\n"
                                l7 = "    Related ports: " + str(port_list) + "\n"
                                l8 = "    Related PIDs: " + str(PID_list) + "\n"

                                print(l1 + l2 + l3 + l4 + l5 + l6 + l7 + l8)
                                file1 = open("ROS-Guardian_log.txt", "a")
                                L = [l1, l2, l3, l4, l5, l6, l7, l8]
                                file1.writelines(L)
                                file1.close()
                                toggle3 = False
                            else:
                                toggle3 = True


                if "<string>unregisterSubscriber</string>" in load:
                    if len(root[1][0][0][0][0]) != 0:
                        for element in root[1][0][0][0][0]:
                            if element[0][1][1][0].text == "unregisterSubscriber":
                                key = element[0][0][1][0][0][1][0].text
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
                                            if ((sys_state.get(o_port) == topic_type.get(o_port)) and (sys_state.get(o_port) == lookup_node.get(o_port))):
                                                stream = os.popen('fuser ' + str(o_port) + '/tcp')
                                                output = stream.read()
                                                if output == '':
                                                    PID = 'UNKNOWN'
                                                else:
                                                    PID = output
                                                    PID_list.append(PID)
                                                node_name = sys_state[o_port]
                                                if not PID_list:
                                                    PID_list = "UNKNOWN"
                                                else:
                                                    for p in port_list:
                                                        stream = os.popen('fuser -k' + str(p) + '/tcp')
                                                        output = stream.read()
                                                        print(output)
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

                if "<string>unregisterService</string>" in load:
                    if len(root[1][0][0][0][0]) != 0:
                        for element in root[1][0][0][0][0]:
                            if element[0][1][1][0].text == "unregisterService":
                                key = element[0][0][1][0][0][1][0].text
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
                                            if ((sys_state.get(o_port) == topic_type.get(o_port)) and (sys_state.get(o_port) == lookup_node.get(o_port))):
                                                stream = os.popen('fuser ' + str(o_port) + '/tcp')
                                                output = stream.read()
                                                if output == '':
                                                    PID = 'UNKNOWN'
                                                else:
                                                    PID = output
                                                    PID_list.append(PID)
                                                node_name = sys_state[o_port]
                                                if not PID_list:
                                                    PID_list = "UNKNOWN"
                                                else:
                                                    for p in port_list:
                                                        stream = os.popen('fuser -k' + str(p) + '/tcp')
                                                        output = stream.read()
                                                        print(output)
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
                                        PID_list = []
                                        port = packet[IP].sport
                                        o_port = port - 2
                                        port_list = [port, o_port]
                                        if (o_port in sys_state.keys()) and (o_port in topic_type.keys()) and (o_port in lookup_node.keys()):
                                            if ((sys_state.get(o_port) == topic_type.get(o_port)) and (sys_state.get(o_port) == lookup_node.get(o_port))):
                                                stream = os.popen('fuser ' + str(o_port) + '/tcp')
                                                output = stream.read()
                                                if output == '':
                                                    PID = 'UNKNOWN'
                                                else:
                                                    PID = output
                                                    PID_list.append(PID)
                                                node_name = sys_state[o_port]
                                                if not PID_list:
                                                    PID_list = "UNKNOWN"
                                                else:
                                                    for p in port_list:
                                                        stream = os.popen('fuser -k' + str(p) + '/tcp')
                                                        output = stream.read()
                                                        print(output)
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

        if (("<?xml version=\'1.0\'?>" in load) or ("<?xml version=\"1.0\"?>" in load)) and packet[IP].dport != 11311:

            try:
                try:
                    xml = re.search('<\?xml version=\'1.0\'\?>[\s\S]*?<\/methodCall>', load).group(0)
                except:
                    xml = re.search('<\?xml version=\"1.0\"\?>[\s\S]*?<\/methodCall>', load).group(0)
                root = ET.fromstring(xml)
                if root[0].text == "shutdown":
                    if toggle:
                        file1 = open("ROS-Guardian_log.txt", "a")
                        l1 = "A rosnode has been killed \n"
                        L = [l1]
                        file1.writelines(L)
                        file1.close()
                        print(l1)
                        toggle = False
                    else:
                        toggle = True
                
                if root[0].text == "publisherUpdate":
                    ip = str(wifi)
                    if ip in load:
                        if ip in root[1][2][0][0][0][0][0].text:
                            topic = root[1][1][0][0].text
                            addr = root[1][2][0][0][0][0][0].text
                            pub_update[root[1][1][0][0].text] = addr

                if root[0].text == "requestTopic":
                    print("hey")
                    if "TCPROS" in load:
                        if root[1][1][0][0].text in pub_update.keys():
                            addr = pub_update.get(root[1][1][0][0].text)
                            dst = str(packet[IP].dport)
                            if dst in addr:
                                if toggle4:
                                    PID_list = []
                                    port = get_key(None, sys_state)
                                    stream = os.popen('fuser ' + str(port) + '/tcp')
                                    output = stream.read()
                                    if output == '':
                                        pass
                                    else:
                                        PID = output
                                        PID_list.append(PID)
                                    if not PID_list:
                                        PID_list = "UNKNOWN"
                                    else:
                                        command = 'fuser -k ' + str(port) + '/tcp'
                                        print(command)
                                        stream = os.popen(command)
                                        # output = stream.read()
                                        # print(output)

                                    topic = root[1][1][0][0].text
                                    node_name = "Unknown"

                                    now = datetime.now()
                                    current_time = now.strftime("%H:%M:%S")
                                    n_name = root[1][0][0][0].text

                                    l1 = "Unusual Activity Detected:" + "\n"
                                    l2 = "    Action: publisherUpdate" + "\n"
                                    l3 = "    Target topic: " + topic + "\n"
                                    l4 = "    Victim subscriber: " + n_name + "\n"
                                    l5 = "    Time: " + current_time + "\n"
                                    l6 = "    Malicious node: " + node_name + "\n"
                                    l7 = "    Related ports: " + str(port) + "\n"
                                    l8 = "    Related PIDs: " + str(PID_list) + "\n"

                                    print(l1 + l2 + l3 + l4 + l5 + l6 + l7 + l8)
                                    file1 = open("ROS-Guardian_log.txt", "a")
                                    L = [l1, l2, l3, l4, l5, l6, l7, l8]
                                    file1.writelines(L)
                                    file1.close()
                                    toggle4 = False
                                else:
                                    toggle4 = True
            except:
                pass
sniff(filter='tcp', iface="lo", prn=packet_callback, store=0, count=0)