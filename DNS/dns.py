from scapy.all import *
from scapy.layers.dns import DNS, DNSRR

simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
simple_udp.bind(('0.0.0.0', 6969))

# Domain-urile

DOMAIN = "calo.ninja"
SUBDOMAIN = "www.calo.ninja"
CNAME = "calo.tplinkdns.com"
TARGET = "79.112.238.175"
DOMAIN_TTL = 900
CNAME_TTL = 300

while True:
    request, adresa_sursa = simple_udp.recvfrom(65535)
    # converitm payload-ul in pachet scapy
    packet = DNS(request)
    dns = packet.getlayer(DNS)
    if dns is not None and dns.opcode == 0: # dns QUERY
        query = dns.qd.qname.decode('utf-8')
        print ("got for : ", query)
        print (packet.summary())
        
        if query == DOMAIN + "." or query == SUBDOMAIN + ".":
            cname = CNAME
        else:
            continue
        
        cname_answer = DNSRR(   # DNS Reply
           rrname=dns.qd.qname, # for question
           ttl=CNAME_TTL,       # DNS entry Time to Live
           type="CNAME",
           rclass="IN",
           rdata=CNAME)     # found at CNAME ca am dynamic dns
           
        a_record = DNSRR(      # DNS Reply pt A record
           rrname=cname + ".", # for question
           ttl=DOMAIN_TTL,     # DNS entry Time to Live
           type="A",
           rclass="IN",
           rdata=TARGET)    
           
        dns_response = DNS(
                          id = packet[DNS].id, # DNS replies must have the same ID as requests
                          qr = 1,              # 1 for response, 0 for query
                          aa = 0,              # Authoritative Answer
                          rd=0,  # apare warning ca aveam recursion desired si not available, 
                          ra=0,  # deci le-am scos doamne ajuta sa nu fi fost recursia parte din cerinta ca scrie dns minimal pt doar doua domenii
                          rcode = 0,           # 0, nicio eroare http://www.networksorcery.com/enp/protocol/dns.htm#Rcode,%20Return%20code
                          qd = packet.qd,      # request-ul original
                          an = cname_answer)   # obiectul de reply
                          
        dns_response.an = dns_response.an / a_record # concatenez A recordu la Cname anwser sa apara ca la dig ambele
        print('sending cname response pt:', query, 'pointing spre: ', cname, ' cu IP-u: ', TARGET)
        print (dns_response.summary())
        simple_udp.sendto(bytes(dns_response), adresa_sursa)
simple_udp.close()
