import socket
import threading
import base64
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Confidentiality: Shared Symmetric Key (The "Clubhouse Password")
SYMMETRIC_KEY = b'8co3-4wQfX4Z_N8hG36qXyVj7xXj9L8_gQ5xXj9L8_g=' 
cipher_suite = Fernet(SYMMETRIC_KEY)

# --- IDENTITY (Non-Repudiation Setup) ---
# 1. Generate My RSA Key Pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# 2. Serialize Public Key to send to others over a socket because oython can't otherwise
my_public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 3. Phonebook: Stores { 'Nickname': PublicKeyObject }
# We need this to verify signatures from specific people.
peers_public_keys = {}

# Synchronization flag: Tracks if at least one peer key has been received.
is_peer_key_received = threading.Event()

nickname = input("Choose your nickname: ")

#Add my own key immediately so the programmatic wait works.
# Initial size of the dictionary is 1.
peers_public_keys[nickname] = public_key 

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 55555))

def sign_message(message_text):
    """Signs the message with MY Private Key to prove I wrote it."""
    signature = private_key.sign(
        message_text.encode('utf-8'),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(sender_name, message_text, signature_b64):
    """
    PRINCIPLE: NON-REPUDIATION
    Checks if the signature matches the message using the sender's Public Key.
    """
    # If the sender is not in the phonebook, verification fails.
    if sender_name not in peers_public_keys:
        return False
    
    sender_key = peers_public_keys[sender_name]
    
    try:
        signature = base64.b64decode(signature_b64)
        sender_key.verify(
            signature,
            message_text.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def send_public_key():
    time.sleep(0.2)
    
    # Tell server: "my next packet is a key, please store it"
    client.send("PUBKEY".encode())

    packet = f"KEY||{nickname}||{my_public_pem.decode('utf-8')}"
    encrypted_packet = cipher_suite.encrypt(packet.encode('utf-8'))

    client.send(encrypted_packet)


def receive():
    global is_peer_key_received
    while True:
        try:
            # Increased buffer size to handle large keys
            message = client.recv(8192)
            
            # 1. Handle Plaintext Server Handshakes
            try:
                decoded = message.decode('utf-8')
                if decoded == 'NICK':
                    client.send(nickname.encode('utf-8'))
                    send_public_key() # Immediately send my ID
                    continue
                if "SERVER:" in decoded:
                    print(decoded)
                    # If someone new joined, resend my key so they have it
                    if "joined" in decoded:
                        send_public_key()
                    continue
            except:
                pass

            # 2. DECRYPT (Confidentiality)
            try:
                decrypted_content = cipher_suite.decrypt(message).decode('utf-8')
                
                # Split the internal packet structure
                parts = decrypted_content.split("||")
                packet_type = parts[0]
                
                if packet_type == "KEY":
                    # Store the new Public Key: KEY||Sender||PEM
                    sender = parts[1]
                    pem_data = parts[2].encode('utf-8')
                    
                    # Store the key if it's NOT my own key and it's new.
                    if sender != nickname and sender not in peers_public_keys:
                        peers_public_keys[sender] = serialization.load_pem_public_key(pem_data)
                        print(f"[SYSTEM] Verified identity established for {sender}")
                        # SIGNAL the writing thread that a key has been received.
                        is_peer_key_received.set()
                    
                elif packet_type == "MSG":
                    # Verify and Print: MSG||Sender||Text||Signature
                    sender = parts[1]
                    text = parts[2]
                    sig = parts[3]
                    
                    # 3. VERIFY (Non-Repudiation)
                    if verify_signature(sender, text, sig):
                        print(f"\n[VERIFIED] {sender}: {text}")
                    else:
                        # This should now only trigger if a hacker tries to impersonate someone.
                        print(f"\n[WARNING: INVALID SIGNATURE] {sender}: {text}")

            except Exception:
                pass # Likely a blob we couldn't decrypt or parse

        except Exception as e:
            print("An error occurred!", e)
            client.close()
            break

def write():
    print("Waiting for key exchange (Handshake)...")
    
    is_peer_key_received.wait(timeout=10)

    if is_peer_key_received.is_set():
        print("Handshake complete. You can now chat.")
    else:
        print("No peer keys received yet, Signatures from others will be verifiable once their keys arrive.")

    while True:
        try:
            text = input("")
            if text:
                signature = sign_message(text)
                
                # 2. Pack it: MSG||Nickname||Text||Signature
                full_packet = f"MSG||{nickname}||{text}||{signature}"
                
                # 3. Encrypt the whole packet (Confidentiality)
                encrypted = cipher_suite.encrypt(full_packet.encode('utf-8'))
                
                client.send(encrypted)
        except:
            print("Error sending message")
            break

receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()
