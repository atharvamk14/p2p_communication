import requests

DISCOVERY_SERVER = 'http://127.0.0.1:5000'

def register(username):
    response = requests.post(f'{DISCOVERY_SERVER}/register', json={"username": username})
    print(response.json())

def send_hello(target_username):
    # Lookup the IP address of the target user
    response = requests.get(f'{DISCOVERY_SERVER}/lookup', params={"username": target_username})
    if response.status_code == 200:
        target_ip = response.json().get('ip_address')
        print(f"Sending 'Hello' to {target_username} at {target_ip}")
        # Here you would add the code to actually send a message to the target IP
    else:
        print("User not found.")

# Example Usage
register('alice')
send_hello('bob')
