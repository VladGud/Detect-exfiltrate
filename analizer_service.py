#!/usr/bin/env python

from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR

from utils import MyConcurrentCollection, SystemEnum, entropy

import queue
import threading
import pandas as pd

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

        self.dictionaryAggreagetedInfo = defaultdict(lambda: [None]*len(SystemEnum.enumAggregateDNS))

    def aggregate(self, data):
        for key in data.keys():
            if data[key][SystemEnum.enumNormalizeTable["ProtocolType"]] == SystemEnum.enumProtocol["DNS"]:
                aggregate_key = \
                    "{} -> {} Protocol: {}".format(data[key][SystemEnum.enumNormalizeTable["IP_SRC"]],\
                            data[key][SystemEnum.enumNormalizeTable["IP_DST"]], "DNS")

                if not self.dictionaryAggreagetedInfo[aggregate_key][SystemEnum.enumAggregateDNS["DOMAINS"]]:
                    self.dictionaryAggreagetedInfo[aggregate_key][SystemEnum.enumAggregateDNS["DOMAINS"]] = \
                        str(data[key][SystemEnum.enumNormalizeTable["BODY"]], encoding)

                    self.dictionaryAggreagetedInfo[aggregate_key][SystemEnum.enumAggregateDNS["AMOUNT_DATA_SENT"]] = \
                        data[key][SystemEnum.enumNormalizeTable["PACKAGE_SIZE"]]

                else:
                    self.dictionaryAggreagetedInfo[aggregate_key][SystemEnum.enumAggregateDNS["DOMAINS"]] += \
                        str(data[key][SystemEnum.enumNormalizeTable["BODY"]], encoding)

                    self.dictionaryAggreagetedInfo[aggregate_key][SystemEnum.enumAggregateDNS["AMOUNT_DATA_SENT"]] += \
                        data[key][SystemEnum.enumNormalizeTable["PACKAGE_SIZE"]]

                ratio = ratio_word_to_domainlen(str(data[key][SystemEnum.enumNormalizeTable["BODY"]], encoding))
                if     (self.dictionaryAggreagetedInfo[aggregate_key][SystemEnum.enumAggregateDNS["LARGEST_RATIO"]] == None or
                        self.dictionaryAggreagetedInfo[aggregate_key][SystemEnum.enumAggregateDNS["LARGEST_RATIO"]] < ratio):
                    self.dictionaryAggreagetedInfo[aggregate_key][SystemEnum.enumAggregateDNS["LARGEST_RATIO"]] = ratio

                if not self.dictionaryAggreagetedInfo[aggregate_key][SystemEnum.enumAggregateDNS["NUMBER_PACKAGES"]]:
                    self.dictionaryAggreagetedInfo[aggregate_key][SystemEnum.enumAggregateDNS["NUMBER_PACKAGES"]] = 1
                else:
                    self.dictionaryAggreagetedInfo[aggregate_key][SystemEnum.enumAggregateDNS["NUMBER_PACKAGES"]] += 1

                self.dictionaryAggreagetedInfo[aggregate_key][SystemEnum.enumAggregateDNS["FREQUENCY"]] = \
                    self.dictionaryAggreagetedInfo[aggregate_key][SystemEnum.enumAggregateDNS["NUMBER_PACKAGES"]] \
                        / data[key][SystemEnum.enumNormalizeTable["TIMESTAMP"]]
                        


        for key in self.dictionaryAggreagetedInfo.keys():
            self.dictionaryAggreagetedInfo[key][SystemEnum.enumAggregateDNS["ENTROPY"]] = \
                entropy(self.dictionaryAggreagetedInfo[key][SystemEnum.enumAggregateDNS["DOMAINS"]])        
            #print("Key: {}".format(key), self.dictionaryAggreagetedInfo[key])

    def clean_aggregated_data(self):
        for key in self.dictionaryAggreagetedInfo.keys():
            if self.dictionaryAggreagetedInfo[key][SystemEnum.enumAggregateDNS["NUMBER_PACKAGES"]] > 100:
                self.dictionaryAggreagetedInfo[key] = [None]*len(SystemEnum.enumAggregateDNS)
            #print("Key: {}".format(key), self.dictionaryAggreagetedInfo[key])


    def run(self):
        ex = 0
        while True:
            if not self.input_collection.empty():
                data = self.input_collection.pop()

                self.aggregate(data)

                self.callback(self.dictionaryAggreagetedInfo)

                self.clean_aggregated_data()
                  
            else:
                time.sleep(0.1)
                ex += 1
                if ex > 10000:
                    self.callback(self.dictionaryAggreagetedInfo)
                    #self.normalizer.clear()
                    return 