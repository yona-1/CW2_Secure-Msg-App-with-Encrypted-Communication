import tkinter as tk
from tkinter import filedialog, messagebox
from integrity import FileHasher, IntegrityChecker

checker = IntegrityChecker()

app = tk.Tk()
app.title("File Integrity Monitoring Tool")
app.geometry("650x600")
try:
    app.iconbitmap("icon.ico")
except:
    pass

# Create tkinter variables AFTER root window creation
hash_algo = tk.StringVar(value="sha256")
filepath_var = tk.StringVar()
username_var = tk.StringVar()


def display_user():
    user_display.delete(0, tk.END)
    user_display.insert(tk.END, f"👤 Welcome, {username_var.get()}")
def browse_file():
    path = filedialog.askopenfilename()
    filepath_var.set(path)
def register_file():
    path = filepath_var.get()
    user = username_var.get()
    algo = hash_algo.get()
    if not path or not user:
        messagebox.showwarning("Error", "Enter your name and select a file.")
        return
    try:
        hasher = FileHasher(path)
        file_hash = hasher.generate_hash(algo)
        metadata = hasher.get_metadata()
        checker.save_hash(path, file_hash, metadata, user)
        messagebox.showinfo("Success", f"{algo.upper()} hash registered.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def verify_file():
    path = filepath_var.get()
    if not path:
        messagebox.showwarning("Error", "Select a file.")
        return
    hasher = FileHasher(path)
    new_hash = hasher.generate_hash(hash_algo.get())
    result = checker.verify_hash(path, new_hash)

    if result is None:
        messagebox.showwarning("Not Found", "No record found for this file.")
    elif result:
        messagebox.showinfo("Integrity OK", "File is untampered.")
    else:
        messagebox.showerror("Changed", "File integrity is compromised!")
def show_metadata():
    path = filepath_var.get()
    metadata = checker.get_metadata(path)
    if metadata:
        info = "\n".join(f"{k}: {v}" for k, v in metadata.items())
        messagebox.showinfo("Metadata", info)
    else:
        messagebox.showwarning("No Record", "No metadata found.")


def delete_record():
    path = filepath_var.get()
    if checker.delete_record(path):
        messagebox.showinfo("Deleted", "Record deleted successfully.")
    else:
        messagebox.showwarning("Not Found", "No such record to delete.")
def reset_fields():
    filepath_var.set("")
    username_var.set("")
    user_display.delete(0, tk.END)
def show_all_records():
    report = checker.get_hash_report()
    if report:
        out = "\n\n".join([f"{k}\nHash: {v['hash']}\nUser: {v['user']}" for k, v in report.items()])
        messagebox.showinfo("Stored Hashes", out)
    else:
        messagebox.showinfo("Empty", "No records yet.")


# Layout
tk.Label(app, text="Your Name:").pack()
tk.Entry(app, textvariable=username_var, width=30).pack()
tk.Button(app, text="Submit Name", command=display_user).pack()

user_display = tk.Listbox(app, height=1)
user_display.pack(pady=5)

tk.Label(app, text="Select File:").pack()
tk.Entry(app, textvariable=filepath_var, width=60).pack()
tk.Button(app, text="Browse", command=browse_file).pack()

tk.Label(app, text="Hash Algorithm:").pack()
tk.OptionMenu(app, hash_algo, "sha256", "sha1", "md5").pack()

tk.Button(app, text="🔐 Register File", command=register_file).pack(pady=5)
tk.Button(app, text="🔍 Verify File", command=verify_file).pack(pady=5)
tk.Button(app, text="📋 Show Metadata", command=show_metadata).pack(pady=5)
tk.Button(app, text="🗑️ Delete Record", command=delete_record).pack(pady=5)
tk.Button(app, text="📑 Show All Records", command=show_all_records).pack(pady=5)
tk.Button(app, text="♻️ Reset", command=reset_fields).pack(pady=5)

app.mainloop()