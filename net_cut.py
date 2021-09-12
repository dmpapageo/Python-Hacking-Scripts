#!/usr/bin/env python
import netfilterqueue

def process_packet(packet):
    print(packet)
    packet.ACCEPT()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()


#trapping requests:
#for targer:
#iptables -I FORWARD -j NFQUEUE --queue-num 0
#for our own machine:
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# iptables -I INPUT -j NFQUEUE --queue-num 0
