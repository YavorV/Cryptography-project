import socket
import threading

HOST = '127.0.0.1'
PORT = 55555

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

clients = []
nicknames = []

# Registry of all public keys we have received
# { nickname: "KEY||nickname||<PEM>" (already encrypted) }
public_key_messages = {}

def broadcast(message, sender_socket=None):
    """Sends a message to all clients except the sender."""
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message)
            except:
                remove(client)

def remove(client):
    """Removes a client from the active list."""
    if client in clients:
        index = clients.index(client)
        nickname = nicknames[index]

        clients.remove(client)
        nicknames.remove(nickname)
        client.close()

        print(f"{nickname} has left the chat.")
        broadcast(f"SERVER: {nickname} left!".encode('utf-8'))

def handle(client, nickname):
    expected_key = False

    while True:
        try:
            message = client.recv(8192)
            if not message:
                remove(client)
                break

            # If the client sends "PUBKEY", the next encrypted message is their key
            if message == b"PUBKEY":
                expected_key = True
                continue

            if expected_key:
                # Store the encrypted key packet exactly as-is
                public_key_messages[nickname] = message
                expected_key = False

                # Broadcast this key packet to everyone else
                broadcast(message, client)
                print(f"[SERVER] Stored and broadcasted key for {nickname}")
                continue

            # Normal encrypted chat message
            broadcast(message, client)

        except Exception:
            remove(client)
            break

def receive():
    print(f"Server listening on {HOST}:{PORT}...")

    while True:
        client, address = server.accept()
        print(f"Connected with {address}")

        #The server asks “Who are you?” and the client replies with their username.
        client.send('NICK'.encode('utf-8'))
        nickname = client.recv(1024).decode('utf-8')

        nicknames.append(nickname)
        clients.append(client)

        print(f"Nickname is {nickname}")

        # --- NEW: Send all previously known public keys to this newcomer
        for stored_key_blob in public_key_messages.values():
            try:
                client.send(stored_key_blob)
            except:
                pass

        broadcast(f"SERVER: {nickname} joined!".encode('utf-8'), client)
        client.send('Connected to server!'.encode('utf-8'))

        # Start thread
        thread = threading.Thread(target=handle, args=(client, nickname))
        thread.start()

if __name__ == "__main__":
    receive()
