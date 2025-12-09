import socket
import threading
import json
import base64
import time
from cryptography.fernet import Fernet

# --- CONFIG ---
HOST = '127.0.0.1'
PORT = 55555
ENCODING = 'utf-8'
DELIMITER = b'<END>' # Critical for separating messages in the stream
SYMMETRIC_KEY = b'8co3-4wQfX4Z_N8hG36qXyVj7xXj9L8_gQ5xXj9L8_g=' 
cipher_suite = Fernet(SYMMETRIC_KEY)

# State
clients = []
client_data = {} # {client_socket: {'nickname': str, 'public_pem': bytes}}

def send_packet(client, data_bytes):
    """Helper to append delimiter and send."""
    try:
        client.sendall(data_bytes + DELIMITER)
    except:
        remove_client(client)

def broadcast(data_bytes, sender_socket=None):
    """Sends data to all except sender."""
    for client in clients:
        if client != sender_socket:
            send_packet(client, data_bytes)

def remove_client(client):
    if client in clients:
        nick = client_data[client]['nickname']
        clients.remove(client)
        del client_data[client]
        client.close()
        print(f"[SYSTEM] {nick} left.")
        
        # Notify others
        msg = f"SERVER: {nick} left!".encode(ENCODING)
        # Encrypt the server announcement so clients can parse it uniformly
        enc_msg = cipher_suite.encrypt(msg)
        broadcast(enc_msg)

def handle_client(client):
    buffer = b""
    try:
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            buffer += chunk
            
            while DELIMITER in buffer:
                message, buffer = buffer.split(DELIMITER, 1)
                
                # Logic to handle specific packet types
                process_message(client, message)
    except:
        pass
    finally:
        remove_client(client)

def process_message(client, message_bytes):
    """Decides what to do with a received packet."""
    
    # 1. Check if it is a Handshake (Unencrypted JSON)
    try:
        # We try to decode as JSON. If it works and has 'public_key_pem', it's a handshake.
        # If it's garbage or encrypted, this block will fail and go to step 2.
        data = json.loads(message_bytes.decode(ENCODING))
        
        if 'public_key_pem' in data:
            # IT IS A HANDSHAKE
            nickname = data['nickname']
            pub_key = base64.b64decode(data['public_key_pem'])
            
            client_data[client] = {'nickname': nickname, 'public_pem': pub_key}
            clients.append(client)
            
            print(f"[Handshake] {nickname} joined.")
            
            # A. Send "CONNECTED" signal
            send_packet(client, b"CONNECTED")
            
            # B. Send existing peers' keys (Encrypted Payload)
            peers = {}
            for c, d in client_data.items():
                if c != client:
                    peers[d['nickname']] = base64.b64encode(d['public_pem']).decode(ENCODING)
            
            payload = json.dumps({'type': 'PEERS', 'keys': peers}).encode(ENCODING)
            enc_payload = cipher_suite.encrypt(payload)
            send_packet(client, enc_payload)
            
            # C. Broadcast NEW_PEER to others (Encrypted Payload)
            new_peer_payload = json.dumps({
                'type': 'NEW_PEER', 
                'nickname': nickname, 
                'key': data['public_key_pem']
            }).encode(ENCODING)
            enc_new_peer = cipher_suite.encrypt(new_peer_payload)
            broadcast(enc_new_peer, client)
            return
            
    except:
        pass # Not a handshake, proceed

    # 2. It's a standard encrypted Chat Message
    # Just relay it to everyone else
    broadcast(message_bytes, client)

def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print("Server listening...")
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    start()
