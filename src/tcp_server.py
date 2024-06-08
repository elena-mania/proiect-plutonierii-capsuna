# TCP Server
import socket
import logging
import time
import random
import string

logging.basicConfig(format=u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level=logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
port = 10000
adresa = '0.0.0.0'  # Listen on all available network interfaces
server_address = (adresa, port)
sock.bind(server_address)
logging.info("Server started on %s and listening on port %d", adresa, port)
sock.listen(5)

while True:
    logging.info('Waiting for connections...')
    conexiune, address = sock.accept()
    logging.info("Connected to %s", address)

    while True:
        try:
            data = conexiune.recv(1024)
            if not data:
                break

            logging.info('Received: "%s"', data.decode('utf-8'))

            # Generate a random message
            mesaj = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
            logging.info('Sending message: "%s"', mesaj)
            conexiune.send(f"Server received: {data.decode('utf-8')}. Server message: {mesaj}".encode('utf-8'))

            time.sleep(2)  # Delay between sending messages

        except Exception as e:
            logging.error('Error: %s', str(e))
            break

    conexiune.close()

sock.close()