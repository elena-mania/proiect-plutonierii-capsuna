[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-24ddc0f5d75046c5622901739e7c5dd533143b0c8e959d652212380cedb1ea36.svg)](https://classroom.github.com/a/DQ11BQYq)
# Proiect Rețele 2023-2024

## Sumar

Pentru proiect trebuie să rezolvați următoarele probleme:
- [Preambul (0p)](#vps)
- [Traceroute (2p)](#trace)
- [DNS Server (1p)](#dns1)
- [DNS Tunnel (3p)](#dns2)
- [ARP Spoofing (1p)](#arp)
- [TCP Hijacking (3p)](#tcp)

### Reguli:
- echipe de maxim 3 persoane (muncă în echipă înseamnă că fiecare coleg poate explica munca celorlalți)
- codul pe care nu îl puteți explica se punctează cu 0
- codul copiat de la alți colegi din alte echipe sau scris cu LLM se punctează cu 0 sau se face raport; codul este verificat cu programe de similaritate și cu un clasificator de identificat cod scris cu LLM
- echipele pot fi formate doar din colegi care sunt in aceeasi serie
- orice cod preluat de pe internet trebuie citat (menționat la început de fișier) și înțeles întru totul
- veți fi punctați pe baza întrebărilor pe care le primiți
- întrebările nu vor tine cont de partea la care ati lucrat cel mai mult
- proiectul trebuie să ruleze în timpul prezentării
- **termen limită:** 09 iunie


<a name="vps"></a> 
## Preambul

Vă încurajez să obțineți un VPS și un domeniu gratuit cu care să faceți teste. Aceste exerciții nu se punctează dar vă poate ajuta pentru rezolvarea temei.

### VPS
Pentru a rezolva exercițiile de mai jos, ar fi bine să aveți acces la un server privat virtual (VPS) cu IP public. Acest lucru vă va ajuta să vă dezvoltați capacitatea de lucru din terminal pe un server la distanță.

Un VPS implică diverse costuri, așa că cel mai important lucru aici este **să nu plătiți nimic**. Pentru asta aveți următoarele opțiuni:

- Oracle Free Tier - 1OCPU/1GB RAM AMDx86_64 sau 4OCPU/24GB RAM ARM https://cloud.oracle.com/compute/instances?region=eu-frankfurt-1 - dacă mergeți pe varianta asta luați regiunea Frankfurt
- DigitalOcean - 200$ credits prin github student pack, [link referal aici](https://m.do.co/c/421a5d7512d3), gratuit pe o perioadă limitată (ar fi bine să nu rămâneți cu restanță)
- mai sunt si altele aici, dar nu la fel de avantajoase: https://github.com/cloudcommunity/Cloud-Free-Tier-Comparison

### Domeniu
Prin github student pack si [name.com](https://www.name.com/partner/github-students) puteți obține un domeniu gratuit. Recomand să vă luați un domeniu pe care să puteți face orice fel de experimente doriți, inclusiv să obțineți un certificat TLS.
Există și o alternativă complet gratuită, dar mai puțin flexibilă, anume să folosiți un subdomeniu gratuit de la [FreeDNS afraid.org](https://freedns.afraid.org/)

### Self-hosting (opțional)
O alternativă la VPS este să aveți un calculator (poate fi si raspberry Pi) în rețeaua de acasă pe care să îl accesați de la distanță. Ca să accesați de la distanță servicii din rețeaua locală de acasă, aveți două opțiuni:

1. Port-forwarding și DNS dinamic - verificați la ISP ce fel de servicii oferă. De ex. [Digi oferă dynamic dns](https://s.digi.ro/gateway/g/ZmlsZVNvdXJjZT1odHRwJTNBJTJGJTJG/c3RvcmFnZWRpZ2lybzEucmNzLXJkcy5y/byUyRnN0b3JhZ2UlMkYyMDIxJTJGMDIl/MkYwNCUyRjEyODQwMzRfMTI4NDAzNF9U/UC1MaW5rLXBvcnQtZncucGRmJmhhc2g9/NGZmZDViNzUwYWY5NGUzMDkyZDg1MjhmOGFkMDAwZmU=.pdf), un serviciu prin care puteți să obțineți un domeniu `.go.ro` pentru IP-ul dinamic de acasă (acest domeniu poate deveni un CNAME pentru domeniul vostru obținut de pe [name.com](https://name.com)). Asignați unui calculator din rețeaua locală o adresă IP fixată (ex. `192.168.66.66`) în funcție de adresa sa fizică. Apoi, prin port forwarding, redirecționați mesajele care intră la router pe un port public (de ex. `80`) către serviciul care rulează pe o adresă locală (de ex. `192.168.66.66:8081`). Procedeul ar funcționa și fără DNS dinamic pentru că IP-ul public de la digi nu se schimbă foarte des.
2. Mesh VPN prin [zero-tier](https://www.zerotier.com/) - o alternativă prin care mai multe noduri să facă parte din aceeași rețea locală virtuală.

Accesul public la un calculator din rețeaua de acasă poate reprezinta o breșă majoră de securitate. Nu lăsați servicii pornite decât dacă v-ați asigurat că sunt bine securizate.

<a name="trace"></a> 
## Traceroute 
Traceroute este o metodă prin care putem urmări prin ce routere trece un pachet pentru a ajunge la destinație.
În funcție de IP-urile acestor noduri, putem afla țările sau regiunile prin care trec pachetele.
Înainte de a implementa tema, citiți explicația felului în care funcționează [traceroute prin UDP](https://www.slashroot.in/how-does-traceroute-work-and-examples-using-traceroute-command). Pe scurt, pentru fiecare mesaj UDP care este în tranzit către destinație, dar pentru care TTL (Time to Live) expiră, senderul primește de la router un mesaj [ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header) de tipul [Time Exceeded TTL expired in transit](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Time_exceeded).

1. (0.5p) Modificați fișierul `src/traceroute.py` și implementați o aplicație traceroute complet funcțională.
1. (0.5p) Folosiți un API sau o bază de date care oferă informații despre locația IP-urilor (de ex. [ip-api](https://ip-api.com), [ip2loc](https://ip2loc.com), [ipinfo](https://ipinfo.io) etc.) și apelați-l pentru fiecare IP public pe care îl obțineți.

Creați un raport text /markdown în repository în care:

1. (0.25p) afișați locațiile din lume pentru rutele către mai multe site-uri din regiuni diferite: din Asia, Africa și Australia căutând site-uri cu extensia .cn, .za, .au. Folositi IP-urile acestora.
1. (0.25p) Afișați: Orașul, Regiunea și Țara (acolo unde sunt disponibile) prin care trece mesajul vostru pentru a ajunge la destinație.
1. (0.25p) Executați codul din mai multe locații: **VPS** creat la preambul, de la facultate, de acasă, de pe o rețea publică și salvați toate rutele obținute într-un fișier pe care îl veți prezenta
1. (0.25p) Afișați rutele prin diverse țări pe o hartă folosind orice bibliotecă de plotare (plotly, matplotlib, etc)


<a name="dns1"></a> 
## Server DNS (1p)
1. Citiți despre DNS în [secțiunea de curs](https://github.com/senisioi/computer-networks/tree/2023/capitolul2#dns).
1. Scrieți codul unei aplicații minimale de tip DNS server. Puteți urmări un tutorial [în Rust aici](https://github.com/EmilHernvall/dnsguide/tree/master) și puteți folosi ca punct de plecare [codul în python disponibil în capitolul 6](https://github.com/senisioi/computer-networks/tree/2023/capitolul6#scapy_dns).
1. Creați-vă un domeniu / nume (name.com, freedns, nume într-o rețea locală sau într-o rețea de containere docker) și configuați serverul DNS să fie responsabil pentru un domeniu și un subdomeniu; testați intrările folosind comanda dig sau nslookup

<a name="dns2"></a> 
## Tunel DNS (3p)
În cadrul acestei teme veți avea de implementat un client și un server care vor utiliza pachete DNS malformate pentru a crea un tunel prin care se pot transmite informații arbitrare.
Este un atac destul de [periculos](https://www.catchpoint.com/network-admin-guide/dns-tunneling) iar această temă are scopul de a vă familiariza cu principiile acestui atac cu scopul de a putea crea metode de protecție pe rețelele cu care veți lucra. Nu încercați să reproduceți metoda pe rețele publice, există [mai multe mijloace](https://www.prosec-networks.com/en/blog/dns-tunneling-erkennen/) prin care se poate descoperi tipul acesta de trafic pe rețea.

Ca model, puteți să vă inspirați din aplicații care fac deja asta, cum ar fi [dnstt](https://www.bamsoftware.com/software/dnstt/), [iodine](https://github.com/yarrick/iodine) și multe altele.


În cele ce urmează vom presupune că lucrăm cu VPS de la Oracle Cloud. Principiile sunt aceleași și dacă alegeți alt tip de cloud sau chiar self-hosting.

1. Citiți despre tuneluri DNS pe pagina https://dnstunnel.de și pe pagina despre [mitigare](https://www.prosec-networks.com/en/blog/dns-tunneling-erkennen/)
1. Deschideți portul UDP 53 pentru conexiuni din exterior, pe OCI trebuie deschis și din [iptables](https://judexzhu.github.io/Iptables-Basic-Knowledge/) și din [rețeaua virtuală VCN](https://stackoverflow.com/a/63648081): `sudo sudo iptables -I INPUT 6 -p udp -m udp --dport 53 -j ACCEPT && sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 8080 -j ACCEPT && sudo netfilter-persistent save` mai multe despre [iptables si aici](https://www.digitalocean.com/community/tutorials/iptables-essentials-common-firewall-rules-and-commands)
1. Pentru a verifica că merge conexiunea, porniți serverul DNS de la punctul anterior și testați-l cu dig, dar opriți resolverul existent `systemctl start systemd-resolved`
1. Configurați intrări NS și A ca în exemplul de pe https://dnstunnel.de și testați cu dig că se face rezolvarea numelor în mod corect 
1. Modificați codul de DNS server de la punctul anterior pentru a putea cere și transfera un fișier de la server la client folosind pachete malformate DNS, modificând query si response packet, [exemplu aici](https://dnstunnel.de/#communication); clientul poate trimite cerere pentru un nume_fisier.domeniu.tunel.live iar serverul răspunde cu pachete TXT care contin fisierul pe bucăți codificat binar
1. Atenție că datele transmise prin protocolul UDP se pot pierde, trebuie să aveți un stop and wait sau fereastră glisantă prin care să vă asigurați că tot fișierul ajunge la destinație; la demo veți prezenați [md5 checksum](https://www.tecmint.com/generate-verify-check-files-md5-checksum-linux/) pentru fișier
1. În cazul în care nu puteți rezolva punctul anterior, primiți 1p pe exercițiul acesta dacă copiați fișierul cu secury copy (scp) folosind o unealtă de DNS tunnelling existentă (iodine, dnstt, ozymandns etc).


### Extra 2p.
Puteți sări peste rezolvarea unui alt exercițiu sau chiar lua 12 la examen dacă faceți tunelul DNS să accepte trafic arbitrar prin care serverul DNS să devină SOCKS5 proxy și să direcționați trafic din browser după modelul [iodine](https://github.com/yarrick/iodine) și [aici](https://medium.com/@darxtrix/tunnel-your-way-to-free-internet-1a2e9120ddc)


<a name="arp"></a> 
## ARP Spoofing și TCP Hijacking 


## Structura containerelor
Partea asta se rezolvă folosind aceeași structură de containere ca în capitolul3. Pentru a construi containerele, rulăm `docker compose up -d`.
Imaginea este construită pe baza fișierul `docker/Dockerfile`, dacă facem modificări în fișier sau în scripturile shell, putem rula `docker-compose build --no-cache` pentru a reconstrui imaginile containerelor.


### Observații
1. E posibil ca tabelel ARP cache ale containerelor `router` și `server` să se updateze mai greu. Ca să nu dureze câteva ore până verificați că funcționează, puteți să le curățați în timp ce sau înainte de a declanșa atacul folosind [comenzi de aici](https://linux-audit.com/how-to-clear-the-arp-cache-on-linux/) `ip -s -s neigh flush all`
2. Orice bucată de cod pe care o luați de pe net trebuie însoțită de comments în limba română, altfel nu vor fi punctate.
3. Atacurile implementante aici au un scop didactic, nu încercați să folosiți aceste metode pentru a ataca alte persoane de pe o rețea locală.



## ARP Spoofing 
[ARP spoofing](https://samsclass.info/124/proj11/P13xN-arpspoof.html) presupune trimiterea unui pachet ARP de tip reply către o țintă pentru a o informa greșit cu privire la adresa MAC pereche pentru un IP. [Aici](https://medium.com/@ismailakkila/black-hat-python-arp-cache-poisoning-with-scapy-7cb1d8b9d242) și [aici](https://www.youtube.com/watch?v=hI9J_tnNDCc) puteți urmări cum se execută un atac de otrăvire a tabelei cache ARP stocată pe diferite mașini.

Arhitectura containerelor este definită aici, împreună cu schema prin care `middle` îi informează pe `server` și pe `router` cu privire la locația fizică (adresa MAC) unde se găsesc IP-urile celorlalți. 


```
            MIDDLE------------\
        subnet2: 198.7.0.3     \
        MAC: 02:42:c6:0a:00:02  \
               forwarding        \ 
              /                   \
             /                     \
Poison ARP 198.7.0.1 is-at         Poison ARP 198.7.0.2 is-at 
           02:42:c6:0a:00:02         |         02:42:c6:0a:00:02
           /                         |
          /                          |
         /                           |
        /                            |
    SERVER <---------------------> ROUTER <---------------------> CLIENT
net2: 198.7.0.2                      |                           net1: 172.7.0.2
MAC: 02:42:c6:0a:00:03               |                            MAC eth0: 02:42:ac:0a:00:02
                           subnet1:  172.7.0.1
                           MAC eth0: 02:42:ac:0a:00:01
                           subnet2:  198.7.0.1
                           MAC eth1: 02:42:c6:0a:00:01
                           subnet1 <------> subnet2
                                 forwarding
```

Fiecare container execută la secțiunea command în `docker-compose.yml` un shell script prin care se configurează rutele. [Cient](https://github.com/retele-2023/proiect/blob/main/src/client.sh) și [server](https://github.com/retele-2023/proiect/blob/main/src/server.sh) setează ca default gateway pe router (anulând default gateway din docker). 

În plus, adaugă ca nameserver 8.8.8.8, dacă vreți să testați [DNS spoofing](https://networks.hypha.ro/capitolul6/#scapy_dns_spoofing). 

[Middle](https://github.com/retele-2023/proiect/blob/main/src/middle.sh) setează `ip_forwarding=1` și regula: `iptables -t nat -A POSTROUTING -j MASQUERADE` pentru a permite mesajelor care sunt [forwardate de el să iasă din rețeaua locală](https://askubuntu.com/questions/466445/what-is-masquerade-in-the-context-of-iptables). 


Rulati procesul de otrăvire a tabelei ARP din diagrama de mai sus pentru containerele `server` și `router` în mod constant, cu un time.sleep de câteva secunde pentru a nu face flood de pachete. (Hint: puteți folosi două [thread-uri](https://realpython.com/intro-to-python-threading/#starting-a-thread) pentru otrăvirea routerului și a serverului).


Pe lângă print-urile și mesajele de logging din programele voastre, rulați în containerul middle: `tcpdump -SntvXX -i any` iar pe `server` faceți un `wget http://old.fmi.unibuc.ro`. Dacă middle este capabil să vadă conținutul HTML din request-ul server-ului, înseamnă că atacul a reușit. Altfel încercați să curățați cache-ul ARP al serverului.

<a name="tcp"></a> 
## TCP Hijacking 

Modificați `tcp_server.py` și `tcp_client.py` din repository `src` și rulați-le pe containerul `server`, respectiv `client` ca să-și trimită în continuu unul altuia mesaje random (generați text sau numere, ce vreți voi). Puteți folosi time.sleep de o secundă/două să nu facă flood. Folosiți soluția de la exercițiul anterior pentru a vă interpune în conversația dintre `client` și `server`.
După ce ați reușit atacul cu ARP spoofing și interceptați toate mesajele, modificați conținutul mesajelor trimise de către client și de către server și inserați voi un mesaj adițional în payload-ul de TCP. Dacă atacul a funcționat atât clientul cât și serverul afișează mesajul pe care l-ați inserat. Atacul acesta se numeșete [TCP hijacking](https://www.geeksforgeeks.org/session-hijacking/) pentru că atacatorul devine un [proxy](https://en.wikipedia.org/wiki/Proxy_server) pentru conexiunea TCP dintre client și server.


### Indicații de rezolvare

1. Puteți urmări exemplul din curs despre [Netfilter Queue](https://networks.hypha.ro/capitolul6/#scapy_nfqueue) pentru a pune mesajele care circulă pe rețeaua voastră într-o coadă ca să le procesați cu scapy.
2. Urmăriți exemplul [DNS Spoofing](https://networks.hypha.ro/capitolul6/#scapy_dns_spoofing) pentru a vedea cum puteți altera mesajele care urmează a fi redirecționate într-o coadă și pentru a le modifica payload-ul înainte de a le trimite (adică să modificați payload-ul înainte de a apela `packet.accept()`).
4. Verificați dacă pachetele trimise/primite au flag-ul PUSH setat. Are sens să alterați `SYN` sau `FIN`?
5. Țineți cont de lungimea mesajului pe care îl introduceți pentru ajusta `Sequence Number` (sau `Acknowledgement Number`?), dacă e necesar.
6. Încercați întâi să captați și să modificați mesajele de pe containerul router pentru a testa TCP hijacking apoi puteți combina exercițiul 1 cu metoda de hijacking.
7. Scrieți pe teams orice întrebări aveți, indiferent de cât de simple sau complicate vi se par.
