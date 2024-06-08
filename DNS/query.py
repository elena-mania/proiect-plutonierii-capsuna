
## Inspiratie:
##  https://medium.com/@darxtrix/tunnel-your-way-to-free-internet-1a2e9120ddc
##  https://www.tecmint.com/generate-verify-check-files-md5-checksum-linux/
##  https://github.com/senisioi/computer-networks/tree/2023/capitolul2
##  https://dnstunnel.de/#communication
##  https://github.com/yarrick/iodine
##  https://dnstunnel.de/



import subprocess
import base64
import hashlib



"""
SCRIPT PENTRU CLIENT, DOAR PENTRU TRANSFER DE FISIERE DNSTUNNELING, DACA VRETI QUERY-URI NORMALE LA DOMENIU SI SUBDOMENIU FOLOSITI:
dig @dns.calo.ninja calo.ninja  SAU dig @dns.calo.ninja capsuna.calo.ninja
"""


def query_dns_for_file(domain, subdomain, server):
    """
    interoghez sv u DNS pentru a obtine fisierul prin TXT.

    dns_server = '157.230.100.133'  # adresa ip la droplet
    domain = 'calo.ninja'
    subdomain = 'fisier.dnstunnel' asta variaza depinzand de ce ceri
    return = continutul fisierului in base64 si checksumu primit
    """
    responses = []
    chunk_index = 0
    md5_checksum = None
    while True:
        query_domain = f"{chunk_index}.{subdomain}.{domain}"
        result = (subprocess.run
            (
            ['dig', '@' + server, query_domain, 'TXT', '+short'], # execut dig, nu mi a mers libraria pt dns queries direct
            capture_output=True,
            text=True
        ))
        # extrag record urile TXT din rezultate
        txt_records = result.stdout.strip().split('\n')
        txt_records = [record.strip('"') for record in txt_records if record]
        if not txt_records:
            break
        if txt_records[0].startswith("MD5:"):  # asta e mds u la final calculat pe sv
            md5_checksum = txt_records[0].split(":")[1]
            break
        responses.extend(txt_records)
        chunk_index += 1
    return responses, md5_checksum


def decode_dns_responses(responses):
    """
    decodific raspunsurile de la dns din base64 in human speech

    responses = Lista cu raspunsurile DNS (codificate in base64) lista cu base64 u
    return = texxtul decodificat
    """
    base64_string = ''.join(responses)  # concatenez toate chunk urile TXT
    file_content = base64.b64decode(base64_string)
    return file_content


def calculate_md5(file_path):
    """
    calculez MD5 a ce am primit

    file_path = unde e in pc, fisierul luat din dns tunneling
    return = MD5 u
    """
    md5_hash = hashlib.md5() # instanta de obiect md5 hash
    with open(file_path, "rb") as file: # binary read mode
        for chunk in iter(lambda: file.read(4096), b""): # 4096 biti o data, mai putin daca nu mai are de unde se opreste la biti empty b""
            md5_hash.update(chunk)  # calculat incrementat la fiecar echunk
    return md5_hash.hexdigest()     # returnez ca si hexadecimal string


# Domain uri
dns_server = '157.230.100.133'  # Adresa ip la droplet
domain = 'calo.ninja'
subdomain = 'bee.dnstunnel'  # Subdomeniul pt tunneling, inlocuieste aici fisier cu numele oricarui .txt din server
                                # optiuni: bee  (bee movie script)
                                # optiuni: largefile  (generat sa fie 1MB random)
                                # optiuni: fisiermare (50 randuri de bee movie script)
                                # optiuni: fisier (un rand de text)

# interoghez sv ul si obtin fisierul, si md5 u
responses, server_md5 = query_dns_for_file(domain, subdomain, dns_server)

# decodific
file_content = decode_dns_responses(responses)

# schimb ultimul octet cu X in fisierul primit, eroare intentionata sa verific daca chiar merge md5, ca in testare mereu au dat match
######  file_content = file_content[:-1] + b'X'

# salvez fisierul
output_file = "received_largefile.txt"
with open(output_file, "wb") as f:
    f.write(file_content)

print(f"Fisierul a fost salvat ca {output_file}")

# calculez md5 la textul primit
received_md5 = calculate_md5(output_file)

# compar md5 u textului primit cu cel trimis de server
if received_md5 == server_md5:
    print("Integritatea fisierului a fost verificata. md5-urile se potrivesc")
    print("MD5 primit:", received_md5)
    print("MD5 a serverului:", server_md5)
else:
    print("Verificarea integritatii fisierului n-a mers ghinion, md5-urile nu se potrivesc")
    print("MD5 primit:", received_md5)
    print("MD5 a serverului:", server_md5)

