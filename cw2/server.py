import socket
import threading
import json
from cryptography.fernet import Fernet
import datetime
# Load encryption key
with open("secret.key", "rb") as key_file:
    secret_key = key_file.read()
cipher_suite = Fernet(secret_key)

host = "127.0.0.1"
port = 5555
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

clients = []
usernames = {}  # client socket -> username
passwords = {}  # username -> password (in-memory)
print(" Server started on port 5555")
def broadcast(message, exclude_client=None):
    """Send message to all connected clients."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    full_message = f"[{timestamp}] {message}"
    print(full_message)
    with open("chat_log.txt", "a", encoding="utf-8") as log_file:
        log_file.write(full_message + "\n")
    encrypted = cipher_suite.encrypt(full_message.encode())
    for client in clients:
        if client != exclude_client:
            try:
                client.send(encrypted)
            except:
                remove_client(client)

def send_user_list():
    """Send active user list to all clients."""
    active_users = list(usernames.values())
    payload = json.dumps({"type": "user_list", "users": active_users})
    encrypted = cipher_suite.encrypt(payload.encode())
    for client in clients:
        try:
            client.send(encrypted)
        except:
            remove_client(client)
def handle_client(client):
    try:
        encrypted_auth = client.recv(4096)
        decrypted_auth = cipher_suite.decrypt(encrypted_auth).decode()
        auth_data = json.loads(decrypted_auth)
        action = auth_data.get("action")
        username = auth_data.get("username")
        password = auth_data.get("password")
    except Exception as e:
        print(f"[ERROR] Auth error: {e}")
        client.close()
        return
    # Registration
    if action == "register":
        if username in passwords:
            client.send(cipher_suite.encrypt("REGISTER_FAILED".encode()))
        else:
            passwords[username] = password
            client.send(cipher_suite.encrypt("REGISTER_SUCCESS".encode()))
        client.close()
        return
    # Login
    elif action == "login":
        if username in passwords and passwords[username] == password:
            client.send(cipher_suite.encrypt("AUTH_SUCCESS".encode()))
        else:
            client.send(cipher_suite.encrypt("AUTH_FAILED".encode()))
            client.close()
            return
    else:
        client.close()
        return

    clients.append(client)
    usernames[client] = username
    broadcast(f" {username} joined the chat!", exclude_client=client)
    send_user_list()
    while True:
        try:
            msg_encrypted = client.recv(4096)
            if not msg_encrypted:
                break
            msg_data = json.loads(cipher_suite.decrypt(msg_encrypted).decode())
            message = msg_data.get("message")
            if message:
                broadcast(f"{username}: {message}")
        except:
            break
    remove_client(client)
def remove_client(client):
    if client in clients:
        clients.remove(client)
        left_user = usernames.pop(client, None)
        if left_user:
            broadcast(f" {left_user} left the chat")
            send_user_list()
    client.close()

def accept_connections():
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()

if __name__ == "__main__":
    accept_connections()
