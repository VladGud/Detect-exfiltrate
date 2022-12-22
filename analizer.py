#!/usr/bin/env python

from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR

from utils import MyConcurrentCollection, SystemEnum
from analizer_service import Aggregator

import queue
import threading
import time

class Analizer:
	def __init__(self, input_col : MyConcurrentCollection, quota, threads_count = 1):
		self.input_col = input_col
		self.consumers = [Aggregator(self.input_col, self.analyze_data) for _ in range(threads_count)]
		self.quota = quota

	def run(self):
		for consumer in self.consumers:
			consumer.start()
		for consumer in self.consumers:
			consumer.join()

	def analyze_data(self, data):
		logfile = open("/var/log/data-exfiltration.log", "a")
		for key in data.keys():
			if data[key][SystemEnum.enumAggregateDNS["ENTROPY"]] > 0.88:
				logfile.write("Detected for a stream {} data exfiltration, based on entropy {}. The data was sent {}\n".format\
					(key, data[key][SystemEnum.enumAggregateDNS["ENTROPY"]], data[key][SystemEnum.enumAggregateDNS["AMOUNT_DATA_SENT"]]))

			if data[key][SystemEnum.enumAggregateDNS["AMOUNT_DATA_SENT"]] > self.quota*1024*1024:
				logfile.write("Detected for a stream {} data exfiltration, based on exceeding the quota {} MB. The data was sent {}\n".format\
					(key, self.quota, data[key][SystemEnum.enumAggregateDNS["AMOUNT_DATA_SENT"]]))
		return

	"""
	#def predict(self):
    #    return [[key, self.model.predict([self.dfMainInfo[key]])] for key in self.dfMainInfo]
	def analyze_data(self, data):
        ex = 0
        
        for key in data.keys:
           	new_aggregate_data[key] = aggregate(data[key])
           	if entropy(new_aggregate_data[time_key][SystemEnum.enumNormalizeTable["BODY"]]) > 3 or new_aggregate_data[time_key][SystemEnum.enumNormalizeTable["QUOTA"]] > quota:
           		incident_flag = true
          		return incident_flag

		    incident_flag  = predict(new_aggregate_data)
		    if(incident_flag)
		       	return incident_flag
	"""	       	