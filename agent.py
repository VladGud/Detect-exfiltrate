#!/usr/bin/env python

from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR

from agent_service import FilterNormalizer
from utils import MyConcurrentCollection

class Agent:
    def __init__(self, output_col : MyConcurrentCollection, threads_count = 1, iface = None):
        self.col = MyConcurrentCollection()
        self.output_col = output_col
        self.consumers = [FilterNormalizer(self.col, self.send_to_analizer) for _ in range(threads_count)]
        self.iface = iface

    def sniff_packets(self):
        """
        Sniff 53 port packets with `iface`, if None (default), then the
        Scapy's default interface is used
        """
        if self.iface:
            # port 80 for http (generally)
            # `process_packet` is the callback
            sniff(filter="port 53", prn=self.col.append, iface=self.iface)
        else:
            # sniff with default interface
            sniff(filter="port 53", prn=self.col.append)

    def run(self):
        for consumer in self.consumers:
            consumer.start()

        self.sniff_packets()

        for consumer in self.consumers:
            consumer.join()

    def send_to_analizer(self, out_data):
        self.output_col.append(out_data)

#pcap = '/path/.../to/.../pcap/.../.pcap'
#pkts = rdpcap(pcap)