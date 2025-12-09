import socket
import threading
import base64
import json
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

#CONFIG
HOST = '127.0.0.1'
PORT = 55555
ENCODING = 'utf-8'
DELIMITER = b'<END>' 
SYMMETRIC_KEY = b'8co3-4wQfX4Z_N8hG36qXyVj7xXj9L8_gQ5xXj9L8_g=' 
cipher_suite = Fernet(SYMMETRIC_KEY)

#KEYS
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
my_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM, 
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

peers_keys = {} # {nickname: rsa_key_object}
nickname = input("Nickname: ")
peers_keys[nickname] = public_key # Trust myself

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

#HELPERS
def send_packet(data_bytes):
    try:
        client.sendall(data_bytes + DELIMITER)
    except:
        print("Failed to send.")

def sign_msg(text):
    sig = private_key.sign(
        text.encode(ENCODING),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode(ENCODING)

def verify_msg(sender, text, sig_b64):
    if sender not in peers_keys: return False
    try:
        peers_keys[sender].verify(
            base64.b64decode(sig_b64),
            text.encode(ENCODING),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except:
        return False

#LOGIC
def receive():
    buffer = b""
    while True:
        try:
            chunk = client.recv(4096)
            if not chunk: break
            buffer += chunk
            
            while DELIMITER in buffer:
                packet, buffer = buffer.split(DELIMITER, 1)
                process_packet(packet)
        except Exception as e:
            print("Disconnected.", e)
            client.close()
            break

def process_packet(packet):
    # 1. Plaintext Control Messages
    if packet == b"CONNECTED":
        print("[SYSTEM] Connected. Waiting for keys...")
        return

    # 2. Encrypted Messages
    try:
        decrypted = cipher_suite.decrypt(packet).decode(ENCODING)
        
        # Check if JSON (Key Exchange)
        if decrypted.startswith('{') and decrypted.endswith('}'):
            data = json.loads(decrypted)
            
            if data['type'] == 'PEERS':
                for nick, key_b64 in data['keys'].items():
                    peers_keys[nick] = serialization.load_pem_public_key(base64.b64decode(key_b64))
                print(f"[SYSTEM] Loaded {len(data['keys'])} peers.")
                
            elif data['type'] == 'NEW_PEER':
                nick = data['nickname']
                key_b64 = data['key']
                peers_keys[nick] = serialization.load_pem_public_key(base64.b64decode(key_b64))
                print(f"[SYSTEM] {nick} joined.")
        
        # Check if Chat Message
        elif "||" in decrypted:
            parts = decrypted.split("||")
            if parts[0] == "MSG":
                sender, text, sig = parts[1], parts[2], parts[3]
                if verify_signature_wrapper(sender, text, sig):
                    print(f"\n[VERIFIED] {sender}: {text}")
                else:
                    print(f"\n[FAKE] {sender}: {text}")
            elif decrypted.startswith("SERVER:"):
                print(f"\n{decrypted}")

    except Exception as e:
        # print("Debug: Packet Error", e) 
        pass

def verify_signature_wrapper(sender, text, sig):
    # Retry logic or Wait logic could go here, but with the
    # current robust handshake, keys should be present.
    if sender not in peers_keys:
        return False
    return verify_msg(sender, text, sig)

def write():
    # Send Handshake First
    handshake = json.dumps({
        'nickname': nickname,
        'public_key_pem': base64.b64encode(my_pem).decode(ENCODING)
    }).encode(ENCODING)
    send_packet(handshake)

    print("Handshake sent. Chatting enabled.")
    
    while True:
        text = input()
        if text.lower() == 'quit': break
        
        sig = sign_msg(text)
        # MSG||Sender||Text||Sig
        payload = f"MSG||{nickname}||{text}||{sig}".encode(ENCODING)
        encrypted = cipher_suite.encrypt(payload)
        send_packet(encrypted)

threading.Thread(target=receive).start()
threading.Thread(target=write).start()
