import tkinter as tk
import random
from tkinter import messagebox
from cryptography.fernet import Fernet

# Generate a secure key (save it somewhere secure!)
key = Fernet.generate_key()
cipher = Fernet(key)

# Store encrypted messages
encrypted_data = []

user_input = ""

def shuffle_keys():
    chars = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    random.shuffle(chars)
    return chars

def key_press(char):
    global user_input
    user_input += char
    entry_var.set("*" * len(user_input))

def delete_char():
    global user_input
    user_input = user_input[:-1]
    entry_var.set("*" * len(user_input))

def submit():
    global user_input
    if user_input:
        encrypted = cipher.encrypt(user_input.encode())
        encrypted_data.append(encrypted)
        messagebox.showinfo("Success", "Password encrypted and stored securely.")
        print("Encrypted:", encrypted)
    user_input = ""
    entry_var.set("")

def decrypt_last():
    if encrypted_data:
        decrypted = cipher.decrypt(encrypted_data[-1]).decode()
        messagebox.showinfo("Decrypted", f"Decrypted Text:\n{decrypted}")
        print("Decrypted:", decrypted)
    else:
        messagebox.showwarning("Warning", "No data to decrypt.")

# GUI
root = tk.Tk()
root.title("Secure Keyboard with Encryption")
root.geometry("450x500")
root.configure(bg="#111111")

entry_var = tk.StringVar()
entry_box = tk.Entry(root, textvariable=entry_var, show="*", font=('Arial', 18), justify="center", state="readonly")
entry_box.pack(pady=10)

# Keyboard
keypad_frame = tk.Frame(root, bg="#111111")
keypad_frame.pack()

buttons = shuffle_keys()
for i, char in enumerate(buttons):
    b = tk.Button(keypad_frame, text=char, font=("Arial", 14), width=4, height=2,
                  command=lambda c=char: key_press(c), bg="#444", fg="white", relief=tk.FLAT)
    b.grid(row=i//6, column=i%6, padx=4, pady=4)

# Controls
ctrl_frame = tk.Frame(root, bg="#111111")
ctrl_frame.pack(pady=20)

tk.Button(ctrl_frame, text="Delete", command=delete_char, bg="red", fg="white", font=("Arial", 12)).pack(side=tk.LEFT, padx=10)
tk.Button(ctrl_frame, text="Submit (Encrypt)", command=submit, bg="green", fg="white", font=("Arial", 12)).pack(side=tk.LEFT, padx=10)
tk.Button(ctrl_frame, text="Decrypt Last", command=decrypt_last, bg="blue", fg="white", font=("Arial", 12)).pack(side=tk.LEFT, padx=10)

# Prevent clipboard copy-paste
entry_box.bind("<Control-c>", lambda e: "break")
entry_box.bind("<Control-v>", lambda e: "break")

root.mainloop()