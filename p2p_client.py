import socket
import threading
import requests
import os
from cryptography.fernet import Fernet
import logging
from requests.exceptions import HTTPError, ConnectionError, RequestException
import tkinter as tk
from tkinter import simpledialog
import rq
from redis import Redis

# Configuration
DISCOVERY_SERVER = 'http://127.0.0.1:5000'
LOCAL_IP = '127.0.0.1'
LISTEN_PORT = 65432  # Example port
KEY = Fernet.generate_key()
CIPHER = Fernet(KEY)

redis_conn = Redis()
queue = rq.Queue(connection=redis_conn)

def register(username, password):
    """Register the client with the discovery server, including error handling and password support."""
    try:
        payload = {
            "username": username,
            "password": password,
            "port": LISTEN_PORT
        }
        response = requests.post(f'{DISCOVERY_SERVER}/register', json=payload)
        response.raise_for_status()  # Checks for HTTP status errors

        # Check response content for application-level success
        response_data = response.json()
        if 'message' in response_data and response_data['message'] == "Registration successful":
            print(f"Registration successful for {username}.")
        else:
            logging.error(f"Registration failed: {response_data.get('error', 'Unknown error')}")
    
    except HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
    except ConnectionError as conn_err:
        logging.error(f"Connection error occurred: {conn_err}")
    except RequestException as req_err:
        logging.error(f"Network error occurred: {req_err}")
    except Exception as err:
        logging.error(f"An error occurred: {err}")

def lookup_user(username):
    """Lookup the IP address and port of a user."""
    response = requests.get(f'{DISCOVERY_SERVER}/lookup', params={"username": username})
    if response.status_code == 200:
        return response.json()
    else:
        print("User not found.")
        return None

def send_message(target_ip, target_port, message):
    try:
        encrypted_message = CIPHER.encrypt(message.encode())
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((target_ip, target_port))
            s.sendall(encrypted_message)
            print(f"Message sent to {target_ip}:{target_port}")
    except socket.error as e:
        print(f"Failed to send message: {e}")
        queue_message(target_ip, target_port, message)

def queue_message(target_ip, target_port, message):
    job = queue.enqueue(send_message, target_ip, target_port, message, job_timeout=300)
    print(f"Message queued with job ID: {job.id}")

def handle_queued_messages():
    while True:
        jobs = queue.jobs
        for job in jobs:
            try:
                result = job.perform()
                if result:
                    job.delete()
            except Exception as e:
                print(f"Error sending queued message: {e}")

def receive_messages():
    """Listen for incoming messages and decrypt them."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('0.0.0.0', LISTEN_PORT))
        server_socket.listen()
        print(f"Listening for messages on port {LISTEN_PORT}...")
        while True:
            conn, addr = server_socket.accept()
            with conn:
                data = conn.recv(1024)
                print(f"Received: {CIPHER.decrypt(data).decode()}")

def load_or_create_key():
    key_file = 'secret.key'
    try:
        with open(key_file, 'rb') as f:
            key = f.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
    return key

def gui_send_message():
    target_username = simpledialog.askstring("Input", "Enter the username to send a message:")
    message = simpledialog.askstring("Input", "Enter your message:")
    user_info = lookup_user(target_username)
    if user_info:
        send_message(user_info['ip_address'], user_info['port'], message)


root = tk.Tk()
root.geometry('400x400')

send_btn = tk.Button(root, text="Send Message", command=gui_send_message)
send_btn.pack(pady=20)

root.mainloop()
threading.Thread(target=handle_queued_messages, daemon=True).start()

# Main execution
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry('400x400')

    send_btn = tk.Button(root, text="Send Message", command=gui_send_message)
    send_btn.pack(pady=20)

    threading.Thread(target=receive_messages, daemon=True).start()

    root.mainloop()

    username = input("Enter your username: ")
    register(username)
    
    threading.Thread(target=receive_messages, daemon=True).start()

    while True:
        target_username = input("Enter the username to send a message to ('exit' to quit): ")
        if target_username.lower() == 'exit':
            break
        user_info = lookup_user(target_username)
        if user_info:
            message = input("Enter your message: ")
            send_message(user_info['ip_address'], user_info['port'], message)
        else:
            print(f"Could not find {target_username}.")
