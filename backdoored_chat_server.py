"""
Toki : Chat App
Group 4 
Akrita Singh - a1915043 
Jian Zhang - a1851092
Reham Mansour - a1744126
Samrawit Ghebremedhin -a1810859 

"""
import asyncio
import websockets
import json
import os
import base64
import bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

# Server configuration
SERVER_PORT = 8765
clients = {}

# Predefined password for demonstration
hashed_password = bcrypt.hashpw(b'password', bcrypt.gensalt()).decode('utf-8')

# Vulnerable authentication function
def vulnerable_authentication(username, password):
    if username == "admin" and bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
        return True
    elif username == "guest":  # Intentional backdoor for testing
        return True
    return False

# AES encryption and decryption
def encrypt_aes(message, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode()

def decrypt_aes(ciphertext, aes_key, iv):
    try:
        ciphertext = base64.b64decode(ciphertext)
        iv = base64.b64decode(iv)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    except Exception as e:
        return str(e)  # Return error message on failure

# RSA encryption and decryption
def rsa_encrypt(public_key_pem, message):
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(encrypted).decode()

def rsa_decrypt(private_key_pem, encrypted_message):
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_message),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted.decode()

# Generate RSA keys (public and private)
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Sign a message with RSA private key
def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

# Verify the message signature with RSA public key
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            base64.b64decode(signature),
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

# AES key generation
def generate_aes_key():
    return os.urandom(32)

async def handle_client(websocket, path):
    try:
        # Authentication step
        auth_data = await websocket.recv()
        auth_data = json.loads(auth_data)

        if not vulnerable_authentication(auth_data["username"], auth_data["password"]):
            await websocket.send(json.dumps({"type": "error", "message": "Authentication failed"}))
            return

        # Generate RSA keys for the client
        client_private_key, client_public_key = generate_rsa_keys()
        client_public_pem = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        client_id = str(id(websocket))
        clients[client_id] = {
            "websocket": websocket,
            "private_key": client_private_key,
            "public_key_pem": client_public_pem
        }

        # Send public key to client
        await websocket.send(json.dumps({"type": "public_key", "public_key": client_public_pem}))

        await websocket.send(json.dumps({"type": "success", "message": "Authenticated"}))

        # After authentication, proceed to handle chat messages
        async for message in websocket:
            data = json.loads(message)
            if data["type"] == "hello":
                handle_hello(data, websocket, client_id)
            elif data["type"] == "chat":
                await handle_chat(data, websocket, client_id)
            elif data["type"] == "public_chat":
                await handle_public_chat(data)
    finally:
        if client_id in clients:
            del clients[client_id]
        await notify_clients_about_disconnection(client_id)

def handle_hello(data, websocket, client_id):
    print(f"Client {client_id} connected.")

async def handle_chat(data, websocket, client_id):
    recipient_id = data["recipient_id"]
    message = data["message"]
    signature = sign_message(clients[client_id]["private_key"], message)  # Sign the message

    if recipient_id in clients:
        recipient_ws = clients[recipient_id]["websocket"]
        await recipient_ws.send(json.dumps({
            "type": "chat",
            "message": message,
            "signature": signature,
            "sender_id": client_id
        }))
    else:
        await websocket.send(json.dumps({"type": "error", "message": "Recipient not connected"}))

async def handle_public_chat(data):
    message = data["message"]
    for client_id, client_data in clients.items():
        recipient_ws = client_data["websocket"]
        signature = sign_message(client_data["private_key"], message)  # Sign public messages
        await recipient_ws.send(json.dumps({"type": "public_chat", "message": message, "signature": signature}))

async def notify_clients_about_disconnection(client_id):
    for client_data in clients.values():
        recipient_ws = client_data["websocket"]
        await recipient_ws.send(json.dumps({"type": "client_update", "clients": [client_id]}))

# Start WebSocket server
start_server = websockets.serve(handle_client, "localhost", SERVER_PORT)

print(f"WebSocket server running on ws://localhost:{SERVER_PORT}")
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
