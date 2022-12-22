#!/usr/bin/env python

from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR

from utils import MyConcurrentCollection, SystemEnum

import threading
import time

class Normalizer:
    def __init__(self):
        self.dfMainInfo = defaultdict(lambda: [None]*len(SystemEnum.enumNormalizeTable))

        self.index_package = 0

    def append(self, protocol_type, packet):
        try:
            if protocol_type == "DNS":
                if IP in packet:
                    ip_src = packet[IP].src
                    ip_dst = packet[IP].dst
                else:
                    return    

                if TCP in packet:
                    sport=packet[TCP].sport
                    dport=packet[TCP].dport   
                elif UDP in packet:
                    sport=packet[UDP].sport
                    dport=packet[UDP].dport 
                else:
                    return 

                if packet.qdcount > 0 and isinstance(packet.qd, DNSQR):
                    name = packet.qd.qname
                elif packet.ancount > 0 and isinstance(packet.an, DNSRR):
                    name = packet.an.rdata

                self.index_package += 1
                self.dfMainInfo[self.index_package][SystemEnum.enumNormalizeTable["ProtocolType"]] =  SystemEnum.enumProtocol["DNS"]
                self.dfMainInfo[self.index_package][SystemEnum.enumNormalizeTable["IP_SRC"]] = ip_src
                self.dfMainInfo[self.index_package][SystemEnum.enumNormalizeTable["IP_DST"]] = ip_dst
                self.dfMainInfo[self.index_package][SystemEnum.enumNormalizeTable["PORT_SRC"]] = sport                
                self.dfMainInfo[self.index_package][SystemEnum.enumNormalizeTable["BODY"]] = name
                self.dfMainInfo[self.index_package][SystemEnum.enumNormalizeTable["PACKAGE_SIZE"]] = len(packet[DNS])
                self.dfMainInfo[self.index_package][SystemEnum.enumNormalizeTable["TIMESTAMP"]] = packet.time
                #print(self.dfMainInfo[self.index_package])

        except KeyError:
            return

    def clear(self):
        self.dfMainInfo = defaultdict(lambda: [None]*len(SystemEnum.enumNormalizeTable))
        self.index_package = 0


class FilterNormalizer(threading.Thread):
    def __init__(self, input_collection: MyConcurrentCollection, callback=None):
        if not callback:
            raise NameError('callback not set')

        threading.Thread.__init__(self)
        self.daemon = True
        self.input_collection = input_collection
        self.number_pkt_processed = 0
        self.callback = callback
        self.times = []
        self.normalizer = Normalizer()

    def run(self):
        self.times.clear()
        ex = 0
        self.number_pkt_processed = 0
        while True:
            if not self.input_collection.empty():
                packet = self.input_collection.pop()

                self.packet_processing(packet)

                if self.number_pkt_processed > 10:
                    self.callback(self.normalizer.dfMainInfo)                    
                    self.number_pkt_processed = 0
                    self.normalizer.clear()   

            else:
                time.sleep(0.1)
                ex += 1
                if ex > 10000:
                    self.callback(self.normalizer.dfMainInfo)                    
                    self.number_pkt_processed = 0
                    self.normalizer.clear()
                    return

    def packet_processing(self, packet):
        if packet.haslayer(DNS):
            self.normalizer.append("DNS", packet)   
            self.number_pkt_processed += 1

        return