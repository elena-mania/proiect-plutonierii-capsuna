# TCP client
import socket
import logging
import time
import random
import string

logging.basicConfig(format=u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level=logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
port = 10000
adresa = '198.7.0.2'  # Replace with the server's IP address
server_address = (adresa, port)

while True:
    try:
        logging.info('Connecting to %s', str(server_address))
        sock.connect(server_address)

        while True:
            # Generate a random message
            mesaj = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
            logging.info('Sending message: "%s"', mesaj)
            sock.send(mesaj.encode('utf-8'))

            data = sock.recv(1024)
            logging.info('Received: "%s"', data.decode('utf-8'))

            time.sleep(2)  # Delay between sending messages

    except Exception as e:
        logging.error('Error: %s', str(e))
        time.sleep(5)  # Wait before reconnecting

    finally:
        logging.info('Closing socket')
        sock.close()