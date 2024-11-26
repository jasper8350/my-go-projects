import socket
import hashlib
import hmac
import time
import struct
import pyotp
import base64 
import secrets

MACHINE_ID_SIZE = 36
NONCE_SIZE = 2
TIMESTAMP_SIZE = 8
SOURCE_IP_SIZE = 4
HMAC_SIZE = 32
OTP_SIZE = 6

def generate_hmac(shared_secret, machine_id, nonce, timestamp, source_ip, totp_value):
    data = (
        machine_id.encode().ljust(MACHINE_ID_SIZE, b'\x00') +
        nonce.to_bytes(NONCE_SIZE, byteorder='big') +
        timestamp.to_bytes(TIMESTAMP_SIZE, byteorder='big') +
        socket.inet_aton(source_ip) +
        totp_value.encode().ljust(OTP_SIZE, b'\x00')
    )

    hmac_algorithm = hashlib.sha256()
    hmac_algorithm.update(shared_secret.encode())
    hmac_algorithm.update(data)
    hmac_value = hmac_algorithm.digest()

    return hmac_value

def verify_otp(shared_secret, machine_id, totp_value):
    hmac_algorithm = hashlib.sha256()
    hmac_algorithm.update(shared_secret.encode())
    hmac_algorithm.update(machine_id.encode())
    hmac_value = hmac_algorithm.digest()

    shared_secret_base32 = base64.b32encode(hmac_value).decode()

    totp = pyotp.TOTP(shared_secret_base32)

    current_timestamp = int(time.time())
    result = totp.verify(totp_value, current_timestamp)

    print(" - OTP  [", totp.at(current_timestamp), "]")

    return result

def verify_packet(packet, shared_secret):
    machine_id = packet[:MACHINE_ID_SIZE].rstrip(b'\x00').decode()
    nonce = int.from_bytes(packet[MACHINE_ID_SIZE:MACHINE_ID_SIZE + NONCE_SIZE], byteorder='big')
    timestamp = int.from_bytes(packet[MACHINE_ID_SIZE + NONCE_SIZE:MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE], byteorder='big')
    source_ip = socket.inet_ntoa(packet[MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE:MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + SOURCE_IP_SIZE])
    totp_value = packet[MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + SOURCE_IP_SIZE:MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + SOURCE_IP_SIZE + OTP_SIZE].rstrip(b'\x00').decode()

    hmac_value = packet[-HMAC_SIZE:]

    hmac_calculated = generate_hmac(shared_secret, machine_id, nonce, timestamp, source_ip, totp_value)
    print("\nCalculated Data:")
    print(" - HMAC [", hmac_calculated.hex(), "]")

    if hmac.compare_digest(hmac_value, hmac_calculated):
        if verify_otp(shared_secret, machine_id, totp_value):
            return True
    return False

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('0.0.0.0', 50001)
server_socket.bind(server_address)

with open('shared_secret', 'r') as file:
    shared_secret = file.read().strip()

while True:
    data, client_address = server_socket.recvfrom(1024)
    received_packet = data

    if verify_packet(received_packet, shared_secret):
        print("OK")
    else:
        print("Fail")

    print("Received Data:")
    print(" - MachineID:", received_packet[:MACHINE_ID_SIZE].rstrip(b'\x00').decode())
    print(" - Nonce:", int.from_bytes(received_packet[MACHINE_ID_SIZE:MACHINE_ID_SIZE + NONCE_SIZE], byteorder='big'))
    print(" - Timestamp:", int.from_bytes(received_packet[MACHINE_ID_SIZE + NONCE_SIZE:MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE], byteorder='big'))
    print(" - Source IP:", socket.inet_ntoa(received_packet[MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE:MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + SOURCE_IP_SIZE]))
    print(" - OTP:", received_packet[MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + SOURCE_IP_SIZE:MACHINE_ID_SIZE + NONCE_SIZE + TIMESTAMP_SIZE + SOURCE_IP_SIZE + OTP_SIZE].rstrip(b'\x00').decode())
    print(" - HMAC:", received_packet[-HMAC_SIZE:].hex())
