import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
import threading
import signal
import os
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    # Base64 encode the encrypted data
    encrypted_data_b64 = base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
    return encrypted_data_b64  # Return as a string

def decrypt_with_aes(encrypted_data_b64, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    # Base64 decode the encrypted data
    encrypted_data = base64.urlsafe_b64decode(encrypted_data_b64.encode('utf-8'))
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

# Prepare encryption parameters
salt = b'Tandon'  # Salt as byte object
password = 'sm12882@nyu.edu'  # Replace with your NYU email
input_string = 'AlwaysWatching'  # Secret data to encrypt

# Encrypt data for TXT record
encrypted_value_b64 = encrypt_with_aes(input_string, password, salt)

# DNS Records
dns_records = {
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: (encrypted_value_b64,),  # Store Base64 string
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },
    # ... other domains
}

def run_dns_server():
    # Create a UDP socket and bind to the local IP and DNS port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('127.0.0.1', 5353))  # Use a non-privileged port

    print("DNS server is running and listening on port 5353...")
    
    while True:
        try:
            # Wait for incoming DNS requests
            data, addr = server_socket.recvfrom(1024)
            print("Received request from:", addr)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            # Process the request here (your existing logic)
            # ...

            # Send response back to the client
            server_socket.sendto(response.to_wire(), addr)
            print("Responding to request:", request.question[0].name.to_text())

        except Exception as e:
            print("Error processing request:", e)
        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)


def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()

if __name__ == '__main__':
    run_dns_server_user()
