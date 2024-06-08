## Inspiratie:
##  https://medium.com/@darxtrix/tunnel-your-way-to-free-internet-1a2e9120ddc
##  https://www.tecmint.com/generate-verify-check-files-md5-checksum-linux/
##  https://github.com/senisioi/computer-networks/tree/2023/capitolul2   aici am pastrat commenturile initiale
#   de la codul din curs, de aceea sunt unele in engleza.
##  https://github.com/EmilHernvall/dnsguide/tree/master
##  https://github.com/oahong/DNS_Tunnel
##  https://dnstunnel.de/#communication
##  https://github.com/yarrick/iodine
##  https://dnstunnel.de/


from scapy.all import *
from scapy.layers.dns import DNS, DNSRR
import base64
import os
import hashlib

# cream un socket udp care asculta portu 53, daca vrei doar de test fara sa opresti systemd doar pune port 6969 si -p 6969 cand dai dig
simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
simple_udp.bind(('0.0.0.0', 53))

# domain-urile hardcodate pt DNS basic
DOMAIN = "calo.ninja"
SUBDOMAIN = "capsuna.calo.ninja"
CNAME = "calo.ninja"
TARGET = "157.230.100.133"
DOMAIN_TTL = 900
CNAME_TTL = 300


# functie sa citesc si sa dau encode la fila
def read_file_in_chunks(file_path, chunk_size=255):
    """
    citesc fisierul cerut si il impart in chunk uri de 255 octeti
    fiecare chuk e codificat in base64 si returnat ca un generator(chestie iterabila python
    chuck size 255 ca atat e maximul
    """
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield base64.b64encode(chunk).decode('utf-8')


def calculate_md5(file_path):
    """
    calculez md5 la fisier
    """
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()


while True:
    # Asteapta o cerere DNS pe portul 53
    request, adresa_sursa = simple_udp.recvfrom(65535)
    # converitm payload-ul in pachet scapy
    packet = DNS(request)
    dns = packet.getlayer(DNS)
    if dns is not None and dns.opcode == 0:  # dns QUERY
        query = dns.qd.qname.decode('utf-8')
        print("got for : ", query)
        print(packet.summary())

        if query == DOMAIN + ".":
            # raspund cu o intregistrare A pt ala principal
            a_record = DNSRR(  # DNS Reply pt A record
                rrname=dns.qd.qname,  # for question
                ttl=DOMAIN_TTL,  # DNS entry Time to Live
                type="A",
                rclass="IN",
                rdata=TARGET
            )
            dns_response = DNS(
                id=packet[DNS].id,  # DNS replies must have the same ID as requests
                qr=1,  # 1 for response, 0 for query
                aa=0,  # Authoritative Answer
                rd=0,
                ra=0,
                rcode=0,  # 0, nicio eroare
                qd=packet.qd,  # request-ul original
                an=a_record  # obiectul de reply
            )
            print('sending A record response pt:', query, 'cu IP-u: ', TARGET)
            print(dns_response.summary())
            simple_udp.sendto(bytes(dns_response), adresa_sursa)

        elif query == SUBDOMAIN + ".":
            # raspund cu CNAME pt subodmneiu si pt principal sa apara ca pe dig u oficial
            cname_answer = DNSRR(  # DNS Reply
                rrname=dns.qd.qname,  # for question
                ttl=CNAME_TTL,  # DNS entry Time to Live
                type="CNAME",
                rclass="IN",
                rdata=CNAME  # found at CNAME, aparent subdomeniu poate fi ori cname ori A record, dar initial aveam self host deci las cname
            )
            a_record = DNSRR(  # DNS Reply pt A record
                rrname=CNAME + ".",  # for question
                ttl=DOMAIN_TTL,  # DNS entry Time to Live
                type="A",
                rclass="IN",
                rdata=TARGET
            )
            dns_response = DNS(
                id=packet[DNS].id,  # DNS replies must have the same ID as requests
                qr=1,  # 1 for response, 0 for query
                aa=0,  # Authoritative Answer
                rd=0,
                ra=0,
                rcode=0,  # 0, nicio eroare
                qd=packet.qd,  # request-ul original
                an=cname_answer  # obiectul de reply
            )
            dns_response.an = dns_response.an / a_record  # concatenez A recordu la Cname anwser sa apara ca la dig ambele
            print('sending cname response pt:', query, 'pointing spre: ', CNAME, ' cu IP-u: ', TARGET)
            print(dns_response.summary())
            simple_udp.sendto(bytes(dns_response), adresa_sursa)

        elif query.endswith(".dnstunnel.calo.ninja."):
            # Extrage indexul fragmentului si numele fisierului din query
            # extrag indexu chunk ului si numele fisierului din query
            chunk_index = int(query.split('.')[0]) # mai intai chunk
            filename = query.split('.')[1] + ".txt" # apoi nume file si adaug ,txt ca asa am in server filele
            file_path = f"/root/{filename}"  # totul e in ~

            if os.path.isfile(file_path):
                # citesc fisierul si impart in fragmente
                chunks = list(read_file_in_chunks(file_path))
                if chunk_index < len(chunks):
                    # daca exista, trimite chunk u
                    chunk = chunks[chunk_index]
                    txt_record = DNSRR(
                        rrname=dns.qd.qname,  # for question
                        ttl=DOMAIN_TTL,  # DNS entry Time to Live
                        type="TXT",
                        rclass="IN",
                        rdata=chunk
                    )
                    dns_response = DNS(
                        id=packet[DNS].id,  # DNS replies must have the same ID as requests
                        qr=1,  # 1 for response, 0 for query
                        aa=0,  # Authoritative Answer
                        rd=0,
                        ra=0,
                        rcode=0,  # 0, nicio eroare
                        qd=packet.qd,  # request-ul original
                        an=txt_record  # obiectul de reply
                    )
                    print(f'sending TXT record chunk {chunk_index} for file: {filename}') # trimit debugging pe server sa stiu unde se afla
                    simple_udp.sendto(bytes(dns_response), adresa_sursa)
                else:

                    # calculam md5 checksum u la fila
                    md5_checksum = calculate_md5(file_path)


                    # trimit md5 u ca txt record separat sa fie mai bine definit
                    txt_record = DNSRR(
                        rrname=dns.qd.qname,  # for question
                        ttl=DOMAIN_TTL,  # DNS entry Time to Live
                        type="TXT",
                        rclass="IN",
                        rdata=f"MD5:{md5_checksum}"
                    )
                    dns_response = DNS(
                        id=packet[DNS].id,  # DNS replies must have the same ID as requests
                        qr=1,  # 1 for response, 0 for query
                        aa=0,  # Authoritative Answer
                        rd=0,
                        ra=0,
                        rcode=0,  # 0, nicio eroare
                        qd=packet.qd,  # request-ul original
                        an=txt_record  # obiectul de reply
                    )
                    print(f'Sending MD5 checksum for file: {filename}')
                    simple_udp.sendto(bytes(dns_response), adresa_sursa)
            else:
                # daca n am gasit fila pe server
                print(f'File not found for query: {query}')

# inchid socket u
simple_udp.close()

## Inspiratie:
##  https://medium.com/@darxtrix/tunnel-your-way-to-free-internet-1a2e9120ddc
##  https://github.com/senisioi/computer-networks/tree/2023/capitolul2
##  https://dnstunnel.de/#communication
##  https://github.com/yarrick/iodine
##  https://dnstunnel.de/