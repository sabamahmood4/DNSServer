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

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

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

def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    return encrypted_data    

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

# Set encryption parameters
salt = b'Tandon'  # Byte-object encoding for salt
password = 'sm12882@nyu.edu'  # Replace with your NYU email
input_string = 'AlwaysWatching'  # Secret data to be exfiltrated

# Encrypt the input string and store as UTF-8 string in DNS record
encrypted_value = encrypt_with_aes(input_string, password, salt)

# Define DNS records, including encrypted data in TXT record for nyu.edu
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.', 'admin.example.com.', 2023081401, 3600, 1800, 604800, 86400
        ),
    },
    'safebank.com.': {dns.rdatatype.A: '192.168.1.102'},
    'google.com.': {dns.rdatatype.A: '192.168.1.103'},
    'legitsite.com.': {dns.rdatatype.A: '192.168.1.104'},
    'yahoo.com.': {dns.rdatatype.A: '192.168.1.105'},
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: (encrypted_value.decode('utf-8'),),  # Store encrypted value as string
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    }
}

def run_dns_server():
    # Create a UDP socket and bind it to the local IP address and DNS port 53
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('127.0.0.1', 53))  # Local IP and standard DNS port

    while True:
        try:
            # Wait for incoming DNS requests
            data, addr = server_socket.recvfrom(1024)
            # Parse the request
            request = dns.message.from_wire(data)
            # Create a response message
            response = dns.message.make_response(request)

            # Get the question from the request
            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            # Check if there is a record in the `dns_records` dictionary that matches the question
            if qname in dns_records and qtype in dns_records[qname]:
                # Retrieve the data for the record and create an appropriate `rdata` object for it
                answer_data = dns_records[qname][qtype]
                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_
