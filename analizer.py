#!/usr/bin/env python

from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR

from utils import MyConcurrentCollection, SystemEnum
from analizer_service import Aggregator

import queue
import threading
import time
import parse
import pandas as pd

class Analizer:
	def __init__(self, input_col : MyConcurrentCollection, quota, threads_count = 1, trainable_data = False, ip_src = None):
		if trainable_data and not ip_src:
			raise NameError("ip_src not set")

		self.input_col = input_col
		self.consumers = [Aggregator(self.input_col, self.analyze_or_create_train_data) for _ in range(threads_count)]
		self.quota = quota
		self.trainable_data = trainable_data
		self.ip_src = ip_src

	def run(self):
		for consumer in self.consumers:
			consumer.start()
		for consumer in self.consumers:
			consumer.join()

	def analyze_or_create_train_data(self, data):
		if self.trainable_data:
			self.create_train_data(data)
		else:
			self.analyze_data(data)

	def create_train_data(self, data):
		for key in data.keys():
			ip_src, ip_dst, protocol = parse.parse("{} -> {} Protocol: {}", key)
			if ip_src == self.ip_src:
				data[key][SystemEnum.enumAggregateDNS["LABEL"]] = 1

		df = pd.DataFrame(data)

		print(df.T)
			

	def analyze_data(self, data):
		logfile = open("/var/log/data-exfiltration.log", "a")
		for key in data.keys():
			if data[key][SystemEnum.enumAggregateDNS["ENTROPY"]] > 0.88:
				logfile.write("Detected for a stream {} data exfiltration, based on entropy {}. The data was sent {}\n".format\
					(key, data[key][SystemEnum.enumAggregateDNS["ENTROPY"]], data[key][SystemEnum.enumAggregateDNS["AMOUNT_DATA_SENT"]]))

			if data[key][SystemEnum.enumAggregateDNS["AMOUNT_DATA_SENT"]] > self.quota*1024*1024:
				logfile.write("Detected for a stream {} data exfiltration, based on exceeding the quota {} MB. The data was sent {}\n".format\
					(key, self.quota, data[key][SystemEnum.enumAggregateDNS["AMOUNT_DATA_SENT"]]))

		logfile.close()

		return

