import socket
import traceback
import requests
import time
import json

# socket de UDP
udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)

# socket RAW de citire a răspunsurilor ICMP
icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
# setam timeout in cazul in care socketul ICMP la apelul recvfrom nu primeste nimic in buffer
icmp_recv_socket.settimeout(3)

def traceroute(ip, port):
    print("Traceroute pentru ip-ul {}".format(ip))
    max_hops = 20
    locations = [] 
    # setam TTL in headerul de IP pentru socketul de UDP
    for TTL in range(1, max_hops + 1):
        udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, TTL)
        udp_send_sock.sendto(b'salut', (ip, port))  # trimite un mesaj UDP catre un tuplu (IP, port)

        # asteapta un mesaj ICMP de tipul ICMP TTL exceeded messages
        try:
            data, addr = icmp_recv_socket.recvfrom(63535)
            addr_ip = addr[0]
            print("TTL={}, Address{}".format(TTL, addr_ip))
            info = ip_info(addr_ip)
            print(f"Oras: {info.get('city', 'N/A')}, Regiune: {info.get('regionName', 'N/A')}, Tara: {info.get('country', 'N/A')}")
            try:
                info["ip"] = ip  #pentru diversificarea pe harta 
                locations.append(info)
            except KeyError:
                continue #daca nu gaseste lon sau lat ignora
            icmp_type = data[0]  # type-ul ICMP il gasim la byte-ul 0 din data
            if icmp_type == 11:  # Type 11 este Time Exceeded
                print(f"ICMP Time Exceeded de la adresa {addr_ip}")
        except Exception as e:
            print(f"Socket error at TTL={TTL}: {str(e)}")
    return locations

def ip_info(ip):
    try:
        url = f'http://ip-api.com/json/{ip}'
        response = requests.get(url) #cerere GET la API 
        return response.json()
    except Exception as e:
        print(f"Nu pot obtine informatii despre IP-ul {ip}. Eroare: {str(e)}")
        return None

ips = ['www.gov.za', 'www.icce-asia.cn', 'www.pm.gov.au']
port = 33534
all_locations = []
for ip in ips: #traceroute + adaugarea pe harta 
    locations = traceroute(ip, port)
    all_locations.extend(locations)

#Daca fac fisierul html aici mi-l face cu root asa ca folosesc un fisier intermediar temporar - aici depun datele
with open("/home/alexandra-marina/Desktop/proiect-retele-2024-plutonierii-cap-una/src/traceroute_results.json", "w") as f:
    json.dump(all_locations, f, indent=4)

print("Rezultatele traceroute au fost salvate în traceroute_results.json")

