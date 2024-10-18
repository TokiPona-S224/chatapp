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
import re
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization, hmac

# Server configuration
SERVER_PORT = 8765
clients = {}

# Set up logging
logging.basicConfig(level=logging.INFO)

# Secure hashed passwords
hashed_passwords = {
    'admin': bcrypt.hashpw(b'password', bcrypt.gensalt()).decode('utf-8'),
    'guest': bcrypt.hashpw(b'guest', bcrypt.gensalt()).decode('utf-8')
}

# Function to validate username
def validate_username(username):
    return re.match(r'^[a-zA-Z0-9_]+$', username) is not None

# Secure authentication function
def authenticate(username, password):
    if username in hashed_passwords and bcrypt.checkpw(password.encode('utf-8'), hashed_passwords[username].encode('utf-8')):
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
        logging.error(f"Decryption failed: {e}")
        return None

# RSA encryption and decryption for key exchange
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

# Generate AES key
def generate_aes_key():
    return os.urandom(32)

# Generate RSA key pair
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# HMAC message signing
def sign_message(message, key):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message.encode())
    return base64.b64encode(h.finalize()).decode()

def verify_signature(message, signature, key):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message.encode())
    try:
        h.verify(base64.b64decode(signature))
        return True
    except:
        return False

async def handle_client(websocket, path):
    try:
        logging.info(f"New connection from {websocket.remote_address}")

        # Authentication step
        auth_data = await websocket.recv()
        auth_data = json.loads(auth_data)

        if not authenticate(auth_data["username"], auth_data["password"]):
            await websocket.send(json.dumps({"type": "error", "message": "Authentication failed"}))
            logging.warning(f"Authentication failed for {auth_data['username']}")
            return

        client_id = auth_data["username"]
        clients[client_id] = websocket
        await websocket.send(json.dumps({"type": "success", "message": "Authenticated"}))

        # Notify others about the new connection
        await notify_clients_about_status(client_id, "online")

        # Proceed to handle chat messages after authentication
        async for message in websocket:
            data = json.loads(message)

            if data["type"] == "private_chat":
                await handle_private_chat(data, websocket)
            elif data["type"] == "public_chat":
                await handle_public_chat(data)
            elif data["type"] == "encrypt_message":
                aes_key = generate_aes_key()
                iv = os.urandom(16)  # Generate IV for AES
                encrypted_message, iv_base64 = encrypt_aes(data["message"], aes_key, iv)
                signature = sign_message(data["message"], aes_key)
                await websocket.send(json.dumps({
                    "type": "encrypted_message",
                    "data": encrypted_message,
                    "iv": iv_base64,
                    "aes_key": base64.b64encode(aes_key).decode(),
                    "signature": signature
                }))
            elif data["type"] == "decrypt_message":
                decrypted_message = decrypt_aes(data["message"], base64.b64decode(data["aes_key"]), data["iv"])
                if decrypted_message and verify_signature(decrypted_message, data["signature"], base64.b64decode(data["aes_key"])):
                    await websocket.send(json.dumps({"type": "decrypted_message", "data": decrypted_message}))
                else:
                    await websocket.send(json.dumps({"type": "error", "message": "Invalid signature or decryption failed"}))
            elif data["type"] == "file":  # <-- File handling starts here
                await handle_file(data, websocket)
    except Exception as e:
        logging.error(f"Error handling client: {e}")
    finally:
        if client_id in clients:
            del clients[client_id]
        await notify_clients_about_status(client_id, "offline")

async def handle_private_chat(data, websocket):
    recipient = data.get("recipient")
    message = data["message"]

    if recipient in clients:
        await clients[recipient].send(json.dumps({"type": "private_chat", "message": message}))
    else:
        await websocket.send(json.dumps({"type": "error", "message": "Recipient not connected"}))

async def handle_public_chat(data):
    message = data["message"]
    timestamp = data.get("timestamp")

    for client_ws in clients.values():
        await client_ws.send(json.dumps({
            "type": "public_chat",
            "message": message,
            "timestamp": timestamp
        }))

async def handle_file(data, websocket):  # <-- New function to handle file
    file_name = data["filename"]
    file_content = data["content"]
    logging.info(f"Received file: {file_name} from {websocket.remote_address}")

    # Decode the Base64 content
    file_data = base64.b64decode(file_content)

    # Save the file to the server's filesystem (optional)
    with open(file_name, 'wb') as f:
        f.write(file_data)
        logging.info(f"File saved as: {file_name}")

    # Send the file content to all connected clients
    for client_ws in clients.values():
        await client_ws.send(json.dumps({
            "type": "file",
            "file_name": file_name,
            "content": data["content"]  # This will be the Base64 encoded content
        }))

async def notify_clients_about_status(client_id, status):
    for client_ws in clients.values():
        await client_ws.send(json.dumps({"type": "user_status", "client_id": client_id, "status": status}))

# Start WebSocket server
start_server = websockets.serve(handle_client, "localhost", SERVER_PORT)

logging.info(f"WebSocket server running on ws://localhost:{SERVER_PORT}")
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
