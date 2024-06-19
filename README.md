
<a name="trace"></a> 
## Traceroute 
Traceroute este o metodă prin care putem urmări prin ce routere trece un pachet pentru a ajunge la destinație.
În funcție de IP-urile acestor noduri, putem afla țările sau regiunile prin care trec pachetele.

1. Traceroute Funcțional: Am modificat src/traceroute.py pentru a crea o aplicație traceroute complet funcțională. Aceasta trimite mesaje UDP cu valori crescătoare ale TTL și primește mesaje ICMP "Time Exceeded".
2. Localizare IP-uri: Am integrat un API de geolocație (ip-api) pentru a obține locațiile IP-urilor routerelor intermediare.
3. Raport Traceroute:
* Locații: Am afișat locațiile (oraș, regiune, țară) pentru rutele către site-uri din Asia (.cn), Africa (.za) și Australia (.au).
* Execuție din Locații Multiple: Am rulat codul din mai multe locații (acasă, facultate, rețea publică, VPS) și am salvat rutele obținute într-un fișier.
* Plotare Rute: Am utilizat biblioteca Plotly pentru a afișa rutele pe o hartă globală.


<a name="dns1"></a> 
## Server DNS
* DNS Server Minim: Am scris o aplicație minimă de tip DNS server care poate rezolva numele de domenii.
* Configurație Domeniu: Am configurat serverul să fie responsabil pentru un domeniu și un subdomeniu.
* Testare: Am folosit comanda dig pentru a verifica rezolvarea corectă a numelor de domenii configurate.

<a name="dns2"></a> 
## Tunel DNS
Un tunel DNS folosește pachete DNS malformate pentru a transmite date arbitrare, o tehnică adesea folosită în atacuri.
* Deschidere Port UDP 53: Am configurat serverul pentru a accepta conexiuni externe pe portul UDP 53.
* Configurare Server DNS: Am verificat că serverul DNS funcționează corect.
* Transfer Fișier: Am modificat serverul DNS pentru a putea transfera fișiere folosind pachete DNS malformate. Am implementat un mecanism de retransmisie pentru a asigura livrarea completă a fișierelor.
* Alternative: Am explorat și utilizat unelte existente de DNS tunnelling ca metodă alternativă.

<a name="arp"></a> 
## ARP Spoofing și TCP Hijacking 


## Structura containerelor
Arhitectura containerelor este definită aici, împreună cu schema prin care `middle` îi informează pe `server` și pe `router` cu privire la locația fizică (adresa MAC) unde se găsesc IP-urile celorlalți. Imaginea este construită pe baza fișierul `docker/Dockerfile`.

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
## ARP Spoofing 

ARP spoofing presupune trimiterea unui pachet ARP de tip reply către o țintă pentru a o informa greșit cu privire la adresa MAC pereche pentru un IP. 
Fiecare container execută la secțiunea command în docker-compose.yml un shell script prin care se configurează rutele. Cient și server setează ca default gateway pe router (anulând default gateway din docker).
Middle setează ip_forwarding=1 și regula: iptables -t nat -A POSTROUTING -j MASQUERADE pentru a permite mesajelor care sunt forwardate de el să iasă din rețeaua locală.
Am rulat procesul de otrăvire a tabelei ARP din diagrama de mai sus pentru containerele server și router în mod constant folosind două thread-uri, cu un time.sleep de câteva secunde pentru a nu face flood de pachete.

<a name="tcp"></a> 
## TCP Hijacking 

Am modificat scripturile `tcp_server.py` și `tcp_client.py` din repository `src` și le-am rulat pe containerul `server`, respectiv `client` ca să-și trimită în continuu unul altuia mesaje random, folosind un time.sleep de o secundă/două să nu facă flood.
După ce am reușit atacul cu ARP spoofing și am interceptat toate mesajele, am modiicat conținutul mesajelor trimise de către client și de către server inserand un mesaj adițional în payload-ul de TCP.
