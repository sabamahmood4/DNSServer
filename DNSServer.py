import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import ast

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

# Encrypt function
def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))  # Call the Fernet encrypt method
    return str(base64.urlsafe_b64encode(encrypted_data), 'utf-8')  # Convert to string for storage

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(base64.urlsafe_b64decode(encrypted_data))  # Call the Fernet decrypt method
    return decrypted_data.decode('utf-8')

# Prepare Encryption Parameters
salt = b'Tandon'  # Salt as a byte-object
password = 'sm12882@nyu.edu'  # Your NYU email
input_string = 'AlwaysWatching'  # Secret data to encrypt

# Encrypt the secret data
encrypted_value = encrypt_with_aes(input_string, password, salt)

# A dictionary containing DNS records mapping hostnames to different types of DNS data.
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],  # List of (preference, mail server) tuples
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
    },
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: (encrypted_value,),  # Store encrypted value as string in a tuple
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },
}

def run_dns_server():
    # Create a UDP socket and bind it to the local IP address and port (the standard port for DNS)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Using UDP
    server_socket.bind(('127.0.0.1', 5353))  # Binding to localhost on port 5353

    while True:
        try:
            # Wait for incoming DNS requests
            data, addr = server_socket.recvfrom(1024)  # Receive data
            print("Received data from:", addr)  # Debug print
            
            request = dns.message.from_wire(data)  # Parse the request
            response = dns.message.make_response(request)  # Create response

            question = request.question[0]  # Get the question
            qname = question.name.to_text()  # Domain name
            qtype = question.rdtype  # Record type
            print("Processing request for:", qname, "Type:", qtype)  # Debug print

            # Check if the record exists in the dns_records dictionary
            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]
                rdata_list = []

                # Handling different DNS record types
                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))
                elif qtype == dns.rdatatype.A:
                    rdata_list.append(dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data))
                elif qtype == dns.rdatatype.TXT:
                    rdata_list.append(dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data[0]))

                for rdata in rdata_list:
                    response.answer.append(dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype))
                    response.answer[-1].add(rdata)

            # Set the AA (Authoritative Answer) flag
            response.flags |= dns.flags.AA
            
            # Send the response back to the client
            print("Responding to request:", qname)
            server_socket.sendto(response.to_wire(), addr)
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
