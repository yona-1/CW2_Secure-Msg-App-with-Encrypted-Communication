import socket
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.fernet import Fernet
import json
import datetime
# Load encryption key
with open("secret.key", "rb") as key_file:
    secret_key = key_file.read()
cipher_suite = Fernet(secret_key)

username = None
client = None  # will be set when connecting

# Colors & fonts
BG_COLOR = "#F5F5F5"
MY_MSG_COLOR = "#DCF8C6"
OTHER_MSG_COLOR = "#FFFFFF"
BTN_COLOR = "#007BFF"
BTN_TEXT_COLOR = "#FFFFFF"
FONT_MAIN = ("Segoe UI", 11)
FONT_BOLD = ("Segoe UI", 11, "bold")
TIME_FONT = ("Segoe UI", 8)

emoji_list = ["😀", "😁", "😅", "😂", "😊", "😇", "😎", "🤔", "😢", "😡", "❤️", "👍", "👋", "🙌", "🎉"]

def connect_to_server():
    global client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 5555))
def register_user():
    global username
    reg_win = tk.Toplevel()
    reg_win.title("Register")
    reg_win.geometry("350x250")
    reg_win.config(bg=BG_COLOR)
    reg_win.resizable(False, False)
    tk.Label(reg_win, text="Register Account", font=("Segoe UI", 14, "bold"), bg=BG_COLOR).pack(pady=15)
    tk.Label(reg_win, text="Username:", bg=BG_COLOR, font=FONT_MAIN).pack()
    user_entry = tk.Entry(reg_win, font=FONT_MAIN, width=25)
    user_entry.pack(pady=5)
    tk.Label(reg_win, text="Password:", bg=BG_COLOR, font=FONT_MAIN).pack()
    pass_entry = tk.Entry(reg_win, show="*", font=FONT_MAIN, width=25)
    pass_entry.pack(pady=5)
    def submit():
        global username
        username = user_entry.get().strip()
        password = pass_entry.get().strip()
        if username and password:
            connect_to_server()
            auth_data = {"action": "register", "username": username, "password": password}
            encrypted_auth = cipher_suite.encrypt(json.dumps(auth_data).encode())
            client.send(encrypted_auth)
            status = cipher_suite.decrypt(client.recv(4096)).decode()
            client.close()
            if status == "REGISTER_SUCCESS":
                messagebox.showinfo("Success", "Account registered! You can now login.")
                reg_win.destroy()
            else:
                messagebox.showerror("Error", "Username already exists.")
        else:
            messagebox.showerror("Error", "Please fill all fields.")

    tk.Button(reg_win, text="Register", bg=BTN_COLOR, fg=BTN_TEXT_COLOR, font=FONT_BOLD,
              relief="flat", width=18, command=submit).pack(pady=15)

def login_user():
    global username
    login_win = tk.Toplevel()
    login_win.title("Login")
    login_win.geometry("350x250")
    login_win.config(bg=BG_COLOR)
    login_win.resizable(False, False)

    tk.Label(login_win, text="Login", font=("Segoe UI", 14, "bold"), bg=BG_COLOR).pack(pady=15)
    tk.Label(login_win, text="Username:", bg=BG_COLOR, font=FONT_MAIN).pack()
    user_entry = tk.Entry(login_win, font=FONT_MAIN, width=25)
    user_entry.pack(pady=5)
    tk.Label(login_win, text="Password:", bg=BG_COLOR, font=FONT_MAIN).pack()
    pass_entry = tk.Entry(login_win, show="*", font=FONT_MAIN, width=25)
    pass_entry.pack(pady=5)

    def submit():
        global username
        username = user_entry.get().strip()
        password = pass_entry.get().strip()
        if username and password:
            connect_to_server()
            auth_data = {"action": "login", "username": username, "password": password}
            encrypted_auth = cipher_suite.encrypt(json.dumps(auth_data).encode())
            client.send(encrypted_auth)
            status = cipher_suite.decrypt(client.recv(4096)).decode()
            if status == "AUTH_SUCCESS":
                login_win.destroy()
                start_chat_window()
            else:
                messagebox.showerror("Error", "Invalid credentials.")
                client.close()
        else:
            messagebox.showerror("Error", "Please fill all fields.")

    tk.Button(login_win, text="Login", bg=BTN_COLOR, fg=BTN_TEXT_COLOR, font=FONT_BOLD,
              relief="flat", width=18, command=submit).pack(pady=15)

def display_message(message):
    chat_area.config(state="normal")
    time_now = datetime.datetime.now().strftime("%H:%M")
    if ": " in message:
        sender, msg_text = message.split(": ", 1)
    else:
        sender, msg_text = "", message

    if sender == username:
        chat_area.insert(tk.END, f"{msg_text}\n", "right")
        chat_area.insert(tk.END, f"{time_now}\n", "time_right")
    else:
        chat_area.insert(tk.END, f"{sender}: {msg_text}\n", "left")
        chat_area.insert(tk.END, f"{time_now}\n", "time_left")

    chat_area.yview(tk.END)
    chat_area.config(state="disabled")

def update_user_list(users):
    user_listbox.delete(0, tk.END)
    user_listbox.insert(tk.END, "Active Users")
    for user in users:
        user_listbox.insert(tk.END, user)

def receive_messages():
    while True:
        try:
            encrypted_msg = client.recv(4096)
            decrypted_msg = cipher_suite.decrypt(encrypted_msg).decode()
            if decrypted_msg.startswith('{"type":'):
                data = json.loads(decrypted_msg)
                if data.get("type") == "user_list":
                    update_user_list(data.get("users", []))
            else:
                display_message(decrypted_msg)
        except:
            break

def send_message(event=None):
    msg = msg_entry.get().strip()
    if msg:
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        payload = {"message": msg, "timestamp": timestamp}
        encrypted_msg = cipher_suite.encrypt(json.dumps(payload).encode())
        client.send(encrypted_msg)
        msg_entry.delete(0, tk.END)

def add_emoji(emoji):
    current_text = msg_entry.get()
    msg_entry.delete(0, tk.END)
    msg_entry.insert(0, current_text + emoji)

def start_chat_window():
    global chat_area, msg_entry, user_listbox
    root.deiconify()
    root.title("Secure Messenger")
    root.geometry("900x600")
    root.config(bg=BG_COLOR)

    main_frame = tk.Frame(root, bg=BG_COLOR)
    main_frame.pack(fill=tk.BOTH, expand=True)

    chat_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, state="disabled", font=FONT_MAIN, bg=BG_COLOR)
    chat_area.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.BOTH, expand=True)

    chat_area.tag_config("right", background=MY_MSG_COLOR, justify="right", lmargin1=100, lmargin2=100, spacing3=5)
    chat_area.tag_config("left", background=OTHER_MSG_COLOR, justify="left", lmargin1=5, lmargin2=5, spacing3=5)
    chat_area.tag_config("time_right", foreground="gray", font=TIME_FONT, justify="right", spacing3=10)
    chat_area.tag_config("time_left", foreground="gray", font=TIME_FONT, justify="left", spacing3=10)

    user_listbox = tk.Listbox(main_frame, width=20, font=FONT_MAIN)
    user_listbox.pack(side=tk.RIGHT, padx=5, pady=5, fill=tk.Y)
    user_listbox.insert(tk.END, "Active Users")

    input_frame = tk.Frame(root, bg=BG_COLOR)
    input_frame.pack(fill=tk.X, padx=5, pady=5)

    global msg_entry
    msg_entry = tk.Entry(input_frame, font=FONT_MAIN)
    msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
    msg_entry.bind("<Return>", send_message)

    send_btn = tk.Button(input_frame, text="Send", command=send_message, bg=BTN_COLOR, fg=BTN_TEXT_COLOR, font=FONT_BOLD, relief="flat")
    send_btn.pack(side=tk.RIGHT, padx=5)

    emoji_frame = tk.Frame(root, bg=BG_COLOR)
    emoji_frame.pack(fill=tk.X, padx=5, pady=3)
    for emoji in emoji_list:
        b = tk.Button(emoji_frame, text=emoji, font=("Segoe UI", 12), width=2, relief="flat",
                      command=lambda e=emoji: add_emoji(e), bg=BG_COLOR)
        b.pack(side=tk.LEFT, padx=1)

    threading.Thread(target=receive_messages, daemon=True).start()

root = tk.Tk()
root.withdraw()

menu_win = tk.Toplevel()
menu_win.title("Welcome to Secure Messenger")
menu_win.geometry("300x200")
menu_win.config(bg=BG_COLOR)
menu_win.resizable(False, False)

tk.Label(menu_win, text="Secure Messenger", font=("Segoe UI", 14, "bold"), bg=BG_COLOR).pack(pady=20)
tk.Button(menu_win, text="Login", bg=BTN_COLOR, fg=BTN_TEXT_COLOR, font=FONT_BOLD, relief="flat", width=15, command=login_user).pack(pady=5)
tk.Button(menu_win, text="Register", bg="#28A745", fg=BTN_TEXT_COLOR, font=FONT_BOLD, relief="flat", width=15, command=register_user).pack(pady=5)
tk.Button(menu_win, text="Exit", bg="#FF4B4B", fg=BTN_TEXT_COLOR, font=FONT_BOLD, relief="flat", width=15, command=root.destroy).pack(pady=15)

root.mainloop()
