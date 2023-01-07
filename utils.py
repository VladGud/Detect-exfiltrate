import queue
import math

def counting_char_in_string(s: str):
    byte_counts = [0]*256
    for i in range(len(byte_counts)):
        byte_counts[i] = s.count(chr(i))

    return byte_counts    
    

def entropy(s: str):
    entropy = 0

    byte_counts = counting_char_in_string(s)

    for count in byte_counts:
        # If no bytes of this value were seen in the value, it doesn't affect
        # the entropy of the file.
        if count == 0:
            continue
  
        # p is the probability of seeing this byte in the file, as a floating-
        # point number
        p = 1.0 * count / len(s)
        entropy -= p * math.log(p, 2)

    return entropy

class MyConcurrentCollection:
    def __init__(self):
        self.collection = queue.Queue()

    def append(self, x):
        self.collection.put(x)

    def pop(self):
        return self.collection.get()

    def __len__(self):
        return self.collection.qsize()

    def __str__(self):
        return f"{len(self)}"

    def print_collection(self):
        return self.collection.queue

    def empty(self):
        return self.collection.empty()

class SystemEnum:
    enumProtocol = {
        "DNS": 0,

        "DoT": 1,

        "DoH": 2,

        "ARP": 3,

        "NTP": 4,
    }

    enumNormalizeTable = {
        "ProtocolType": 0,

        "BODY": 1,

        "PACKAGE_SIZE": 2,

        "IP_SRC": 3,

        "IP_DST": 4,

        "PORT_SRC": 5,

        "TIMESTAMP": 6,
    }

    enumAggregateDNS = {
        "DOMAINS": 0,

        "AMOUNT_DATA_SENT": 1,

        "ENTROPY": 2,

        #The largest ratio of the largest word to the total length of the domain
        "LARGEST_RATIO": 3,

        "NUMBER_PACKAGES": 4,

        "FREQUENCY": 5,

        "LABEL": 6,
    }