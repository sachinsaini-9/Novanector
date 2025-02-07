# Conducting Risk Assessments to Identify Vulnerabilities & Threats (TASK-1)

import nmap

def scan_network(target_ip):
    scanner = nmap.PortScanner()
    scanner.scan(target_ip, '1-1024')  

    for host in scanner.all_hosts():
        print(f"Scanning Host: {host}")
        for protocol in scanner[host].all_protocols():
            print(f"Protocol: {protocol}")
            for port in scanner[host][protocol].keys():
                state = scanner[host][protocol][port]['state']
                print(f"Port: {port} | State: {state}")

# Example 
scan_network("192.168.1.1")


# Develop & Enforce Security Policies (TASK-2)

import re

def check_password_strength(password):
    if (len(password) < 8 or
        not re.search("[A-Z]", password) or
        not re.search("[a-z]", password) or
        not re.search("[0-9]", password) or
        not re.search("[!@#$%^&*]", password)):
        print("Weak password! Use a stronger one.")
    else:
        print("Password is strong.")

# Example
check_password_strength("Test@123")  


# Access Controls, & Authentication  to protect data confidentiality (TASK-3)

user_roles = {
    "admin": ["read", "write", "delete"],
    "user": ["read", "write"],
    "guest": ["read"]
}

def check_access(role, action):
    if action in user_roles.get(role, []):
        print(f"✅ Access granted for {role} to perform '{action}'.")
    else:
        print(f"❌ Access denied for {role} to perform '{action}'.")

# Example
check_access("admin", "delete")  # Allowed
check_access("guest", "write")   # Denied


# Implement Encryption and Decryption  (TASK-4)

from Crypto.Cipher import AES
import base64

def pad(data):
    return data + (16 - len(data) % 16) * ''

def encrypt_AES(plain_text, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(plain_text).encode('utf-8'))
    return base64.b64encode(encrypted_text).decode('utf-8')

def decrypt_AES(encrypted_text, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decrypted_text = cipher.decrypt(base64.b64decode(encrypted_text))
    return decrypted_text.decode('utf-8').strip()

# Example 
key = "thisisaverysecret"  # 16-byte key
plain_text = "Confidential Data"

encrypted_data = encrypt_AES(plain_text, key)
decrypted_data = decrypt_AES(encrypted_data, key)

print("AES Encrypted:", encrypted_data)
print("AES Decrypted:", decrypted_data)


# Monitor Network Traffic & Systems for Suspicious Activity (TASK-5)

import os

def run_snort():
    os.system("sudo snort -A console -q -c /etc/snort/snort.conf -i eth0")

run_snort()
 


# Conduct Regular Security Audits & Penetration Testing (TASK-6)


import subprocess

def scan_website(target_url):
    print(f"Scanning {target_url} for vulnerabilities...")
    command = ["nikto", "-h", target_url]
    process = subprocess.run(command, capture_output=True, text=True)
    print(process.stdout)

# Example 
scan_website("http://example.com")  # Website URL


# compliance with industry regulations and standards.(TASK-7)

def check_compliance():
    compliance_checklist = {
        "Data Encryption": True,
        "Access Controls": True,
        "Multi-Factor Authentication": True,
        "Regular Security Audits": True,
        "Incident Response Plan": False  
    }

    for item, status in compliance_checklist.items():
        print(f"{item}: {'✔️' if status else '❌'}")

check_compliance()
