import socket
import threading
import requests
import sqlite3
from cryptography.fernet import Fernet
import os

# Configuration
DISCOVERY_SERVER = 'http://127.0.0.1:5000'
LOCAL_IP = '127.0.0.1'
LISTEN_PORT = 65432  # Example port

# Key Management
KEY_FILE = 'fernet_key.txt'

def generate_key():
    """Generates and stores a Fernet key if not already present."""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as file:
            file.write(key)
    else:
        print("Key already exists.")

def load_key():
    """Loads the Fernet key from the file."""
    try:
        with open(KEY_FILE, 'rb') as file:
            return file.read()
    except FileNotFoundError:
        print("Key file not found. Generating a new key.")
        generate_key()
        return load_key()

key = load_key()  # Load or generate the key
cipher_suite = Fernet(key)

def register(username):
    """Register the client with the discovery server."""
    try:
        response = requests.post(f'{DISCOVERY_SERVER}/register', json={"username": username, "port": LISTEN_PORT})
        if response.ok:
            print(f"Registration successful: {response.json()}")
        else:
            print(f"Registration failed: {response.text}")
            exit(1)
    except requests.RequestException as e:
        print(f"Registration error: {e}")
        exit(1)

def encrypt_message(message):
    """Encrypt a message."""
    return cipher_suite.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message):
    """Decrypt a message."""
    return cipher_suite.decrypt(encrypted_message.encode()).decode()

def listen_for_messages():
    """Listen for incoming messages on the predefined port."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((LOCAL_IP, LISTEN_PORT))
    server_socket.listen()
    print(f"Listening for messages on port {LISTEN_PORT}...")
    while True:
        client_socket, addr = server_socket.accept()
        with client_socket:
            encrypted_message = client_socket.recv(1024).decode()
            print(f"Encrypted message from {addr}: {encrypted_message}")
            print(f"Decrypted message: {decrypt_message(encrypted_message)}")

def send_message_async(target_info, message):
    """Send a message to another client asynchronously."""
    target_ip, target_port = target_info
    encrypted_message = encrypt_message(message)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((target_ip, target_port))
            s.sendall(encrypted_message.encode())
            print("Message sent successfully.")
        except socket.error as e:
            print(f"Failed to send message: {e}")

def initiate_send_message(username, target_username, message):
    """Initiates the process of sending a message."""
    try:
        response = requests.get(f'{DISCOVERY_SERVER}/lookup', params={"username": target_username})
        if response.ok:
            target_info = response.json()
            threading.Thread(target=send_message_async, args=((target_info['ip_address'], target_info['port']), message)).start()
        else:
            print("User not found.")
    except requests.RequestException as e:
        print(f"Error looking up user: {e}")

def init_db():
    """Initialize the SQLite database for storing messages."""
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS messages (date text, from_user text, to_user text, message text)''')
    conn.commit()
    conn.close()

if __name__ == "__main__":
    generate_key()  # Ensure key exists
    key = load_key()  # Load the key
    cipher_suite = Fernet(key)  # Initialize cipher suite
    
    init_db()  # Initialize the database
    threading.Thread(target=listen_for_messages, daemon=True).start()
    
    username = input("Enter your username: ")
    register(username)

    while True:
        target_username = input("Enter the username you want to send a message to ('exit' to quit): ")
        if target_username.lower() == 'exit':
            break
        message = input("Enter your message: ")
        initiate_send_message(username, target_username, message)
