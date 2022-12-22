#!/usr/bin/env python

from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR

from utils import MyConcurrentCollection, SystemEnum, entropy

import queue
import threading

encoding = 'utf-8'

def ratio_word_to_domainlen(s: str):
    word_list = s.split(".")
    ratio = len(max(word_list, key=len))/len(s)
    return ratio

class Aggregator(threading.Thread):
    def __init__(self, input_collection: MyConcurrentCollection, callback=None):
        if not callback:
            raise NameError('callback not set')

        threading.Thread.__init__(self)
        self.daemon = True
        self.input_collection = input_collection
        self.callback = callback

        self.dfAggreagetedMainInfo = defaultdict(lambda: [None]*len(SystemEnum.enumAggregateDNS))

    def aggregate(self, data):
        for key in data.keys():
            if data[key][SystemEnum.enumNormalizeTable["ProtocolType"]] == SystemEnum.enumProtocol["DNS"]:
                aggregate_key = \
                    "{} -> {}".format(data[key][SystemEnum.enumNormalizeTable["IP_SRC"]], data[key][SystemEnum.enumNormalizeTable["IP_DST"]])

                if not self.dfAggreagetedMainInfo[aggregate_key][SystemEnum.enumAggregateDNS["Domains"]]:
                    self.dfAggreagetedMainInfo[aggregate_key][SystemEnum.enumAggregateDNS["Domains"]] = \
                        str(data[key][SystemEnum.enumNormalizeTable["BODY"]], encoding)
                    self.dfAggreagetedMainInfo[aggregate_key][SystemEnum.enumAggregateDNS["AMOUNT_DATA_SENT"]] = \
                        data[key][SystemEnum.enumNormalizeTable["PACKAGE_SIZE"]]
                else:
                    self.dfAggreagetedMainInfo[aggregate_key][SystemEnum.enumAggregateDNS["Domains"]] += \
                        str(data[key][SystemEnum.enumNormalizeTable["BODY"]], encoding)
                    self.dfAggreagetedMainInfo[aggregate_key][SystemEnum.enumAggregateDNS["AMOUNT_DATA_SENT"]] += \
                        data[key][SystemEnum.enumNormalizeTable["PACKAGE_SIZE"]]
                ratio = ratio_word_to_domainlen(str(data[key][SystemEnum.enumNormalizeTable["BODY"]], encoding))
                if     (self.dfAggreagetedMainInfo[aggregate_key][SystemEnum.enumAggregateDNS["LARGEST_RATIO"]] == None or
                        self.dfAggreagetedMainInfo[aggregate_key][SystemEnum.enumAggregateDNS["LARGEST_RATIO"]] < ratio):
                    self.dfAggreagetedMainInfo[aggregate_key][SystemEnum.enumAggregateDNS["LARGEST_RATIO"]] = ratio


        for key in self.dfAggreagetedMainInfo.keys():
            self.dfAggreagetedMainInfo[key][SystemEnum.enumAggregateDNS["ENTROPY"]] = \
                entropy(self.dfAggreagetedMainInfo[key][SystemEnum.enumAggregateDNS["Domains"]])        
            print("Key: {}".format(key), self.dfAggreagetedMainInfo[key])


    def clear(self):
        self.dfMainInfo = defaultdict(lambda: [None]*len(self.enumNormalizeTable))
        self.index_package = 0

    def run(self):
        ex = 0
        while True:
            if not self.input_collection.empty():
                data = self.input_collection.pop()

                self.aggregate(data)

                self.callback(self.dfAggreagetedMainInfo)
                  
            else:
                time.sleep(0.1)
                ex += 1
                if ex > 10000:
                    self.callback(self.dfAggreagetedMainInfo)
                    #self.normalizer.clear()
                    return

    def packet_processing(packet):
        if packet.haslayer(DNS):
            self.normalizer.append("DNS", packet)   
            self.number_pkt_processed += 1

        return    