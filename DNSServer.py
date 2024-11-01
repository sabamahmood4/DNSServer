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
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key


def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    # Directly convert to a string representation
    return str(base64.urlsafe_b64encode(encrypted_data), 'utf-8')


def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data_bytes = base64.urlsafe_b64decode(encrypted_data)
    return f.decrypt(encrypted_data_bytes).decode('utf-8')


# Prepare encryption parameters
salt = b'Tandon'  # Salt as byte object
password = 'sm12882@nyu.edu'  # Your NYU email
input_string = 'AlwaysWatching'  # Secret data to encrypt

# Encrypt data and store in a TXT-compatible format
encrypted_value = encrypt_with_aes(input_string, password, salt)

# DNS records dictionary
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
        dns.rdatatype.TXT: (str(encrypted_value),),  # Store encrypted value as string for TXT
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    }
}


def run_dns_server():
    # Create a UDP socket and bind to the local IP and DNS port 53
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('127.0.0.1', 5353))

    while True:
        try:
            # Wait for incoming DNS requests
            data, addr = server_socket.recvfrom(1024)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            # Get the question from the request
            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            # Check if record exists in dns_records dictionary
            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]
                rdata_list = []

                # Handle MX record
                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))

                # Handle SOA record
                elif qtype == dns.rdatatype.SOA:
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata = SOA(dns.rdataclass.IN, dns.rdatatype.SOA, mname, rname, serial, refresh, retry, expire,
                                minimum)
                    rdata_list.append(rdata)

                # Handle other record types
                else:
                    if isinstance(answer_data, str):
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                    else:
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, data) for data in answer_data]

                for rdata in rdata_list:
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                    rrset.add(rdata)
                    response.answer.append(rrset)

            # Set Authoritative Answer (AA) flag
            response.flags |= 1 << 10

            # Send response back to the client
            server_socket.sendto(response.to_wire(), addr)
            print("Responding to request:", qname)

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
