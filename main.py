#!/usr/bin/env python

from agent import Agent
from analizer import Analizer
from utils import MyConcurrentCollection

import threading
import argparse
import time

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Packet Sniffer, this is useful when you're need to analyze packets to detect data exfiltration")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    args = parser.parse_args()
    iface = args.iface

    output_col_agent = MyConcurrentCollection()
    agent = Agent(output_col=output_col_agent, threads_count=3, iface = iface)
    analizer = Analizer(input_col=output_col_agent, quota=100, threads_count=3, trainable_data = True, ip_src = "192.168.42.136")
   
    thread_agent = threading.Thread(target=agent.run, args=())
    thread_analizer = threading.Thread(target=analizer.run, args=())
    thread_agent.start()
    thread_analizer.start()
    
    """
    while True:
        while not output_col_agent.empty():
            print(output_col_agent.pop())
        time.sleep(2)
    """
    
    thread_agent.join()
    thread_analizer.join()