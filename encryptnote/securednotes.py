import os
import tkinter as tk
from tkinter import *
from tkinter import messagebox, filedialog
from cryptography.fernet import Fernet

generated_key = ""
saved_texts = []

def generate_one_time_key(entry_genkey, button_genkey):
    global generated_key
    
    if os.path.isfile("keyfile.key"):
        with open("keyfile.key", "rb") as key_file:
            generated_key = key_file.read()
        button_genkey.config(state="disabled")
        messagebox.showinfo("Info", "A key has already been generated.")
    else:
        generated_key = Fernet.generate_key()
        with open("keyfile.key", "wb") as key_file:
            key_file.write(generated_key)
        
        entry_genkey.config(state="normal")
        entry_genkey.delete(0, END)
        entry_genkey.insert(0, generated_key)
        entry_genkey.config(state="readonly")
        button_genkey.config(bg="red", fg="white", state="disabled")

def encrypt():
    if not text1.get(1.0, END).strip():
        messagebox.showerror("Error", "Please enter some text before encrypting.")
        return
    
    tk1 = Toplevel(tk)
    tk1.geometry("800x600")
    tk1.title("Encrypt")

    image_icon = PhotoImage(file="locked.png")
    tk1.iconphoto(False, image_icon)

    def encrypt_text():
        if not os.path.isfile("keyfile.key"):
            messagebox.showerror("Error", "No encryption key found. Please generate a key first.")
            return

        with open("keyfile.key", "rb") as key_file:
            stored_key = key_file.read()

        provided_key = entry_key.get()

        if provided_key != stored_key.decode():
            messagebox.showerror("Error", "Incorrect encryption key.")
            return

        text_to_encrypt = text1.get(1.0, END)
        cipher_suite = Fernet(stored_key)
        encrypted_text = cipher_suite.encrypt(text_to_encrypt.encode())

        cipherText.delete(1.0, END)
        cipherText.insert(END, encrypted_text.decode())
        
        saved_texts.append(encrypted_text.decode())

    button_genkey = Button(tk1, text="Generate a One-Time Key", height="3", width=25, bg="green", fg="white", bd=1,
                           command=lambda: generate_one_time_key(entry_genkey, button_genkey))
    button_genkey.place(x=20, y=25)

    code = StringVar()
    entry_genkey = Entry(tk1, textvariable=code, width=50, bd=1, font=("Roboto", 12), state="disabled")
    entry_genkey.place(x=20, y=100)

    label_key = Label(tk1, text="Enter the secret key for encryption:", fg="black", font=("Roboto", 12))
    label_key.place(x=15, y=150)

    code = StringVar()
    entry_key = Entry(tk1, textvariable=code, width=50, bd=1, font=("Roboto", 12), show="*")
    entry_key.place(x=20, y=200)

    cipherLabel = Label(tk1, text="Cipher Text (Encrypted Text):", fg="black", font=("Roboto", 12)).place(x=15, y=250)
    cipherText = Text(tk1, font="Roboto", bg="white", relief=GROOVE, wrap=WORD, bd=2)
    cipherText.place(x=20, y=300, width=500, height=200)

    button_encryptText = Button(tk1, text="Encrypt the Text", height="2", width=25, bg="#FFFFFF", fg="black", bd=2,
                                command=encrypt_text)
    button_encryptText.place(x=20, y=550)

    button_saveNote = Button(tk1, text="Save", height="2", width=25, bg="#FFFFFF", fg="black", bd=2,
                             command=save_encrypted_text)
    button_saveNote.place(x=230, y=550)

def decrypt():
    if not text1.get(1.0, END).strip():
        messagebox.showerror("Error", "Please enter some text before decrypting.")
        return
    
    tk2 = Toplevel(tk)
    tk2.geometry("800x600")
    tk2.title("Decrypt")

    image_icon = PhotoImage(file="locked.png")
    tk2.iconphoto(False, image_icon)

    def decrypt_text():
        # Check if the .key file exists
        if not os.path.isfile("keyfile.key"):
            messagebox.showerror("Error", "No encryption key found. Please generate a key first.")
            return
        
        # Read the encryption key from the .key file
        with open("keyfile.key", "rb") as key_file:
            stored_key = key_file.read()

        provided_key = entry_key1.get()

        # Compare the provided key with the stored key
        if provided_key != stored_key.decode():
            messagebox.showerror("Error", "Incorrect decryption key.")
            return

        # Decrypt the text
        cipher_text = text1.get(1.0, END)
        cipher_suite = Fernet(stored_key)
        decrypted_text = cipher_suite.decrypt(cipher_text.encode())

        # Display the decrypted text
        plainText.delete(1.0, END)
        plainText.insert(END, decrypted_text.decode())

    label_key1 = Label(tk2, text="Enter the secret key for decryption:", fg="black", font=("Roboto", 12))
    label_key1.place(x=15, y=50)

    code1 = StringVar()
    entry_key1 = Entry(tk2, textvariable=code1, width=50, bd=1, font=("Roboto", 12), show="*")
    entry_key1.place(x=20, y=100)

    plainLabel = Label(tk2, text="Plain Text (Decrypted Text):", fg="black", font=("Roboto", 12)).place(x=20, y=150)
    plainText = Text(tk2, font="Roboto", bg="white", relief=GROOVE, wrap=WORD, bd=2)
    plainText.place(x=20, y=200, width=500, height=200)

    button_decryptText = Button(tk2, text="Decrypt the Text", height="2", width=25, bg="#FFFFFF", fg="black", bd=2,
                                command=decrypt_text)
    button_decryptText.place(x=20, y=550)

def open_text_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "r") as file:
            text_content = file.read()
            text1.delete(1.0, END)
            text1.insert(END, text_content)

def save_encrypted_text():
    global saved_texts
    if not saved_texts:
        messagebox.showwarning("Warning", "No encrypted text to save.")
        return

    # Open the savednotes.txt file in append mode
    with open("savednotes.txt", "a") as file:
        for text in saved_texts:
            file.write(text + "\n")

    messagebox.showinfo("Info", "Encrypted text saved successfully.")

def view_saved_texts():
    try:
        with open("savednotes.txt", "r") as file:
            saved_texts = file.readlines()
    except FileNotFoundError:
        messagebox.showerror("Error", "No saved texts found.")
        return

    if not saved_texts:
        messagebox.showwarning("Warning", "No saved texts found.")
        return

    tk_view = Toplevel(tk)
    tk_view.geometry("600x400")
    tk_view.title("View Saved Texts")

    image_icon = PhotoImage(file="locked.png")
    tk_view.iconphoto(False, image_icon)

    text_box = Text(tk_view, font=("Roboto", 12), wrap=WORD, bg="white", bd=2)
    text_box.pack(fill=BOTH, expand=YES)

    for i, text in enumerate(saved_texts, 1):
        text_box.insert(END, f"Encrypted Text {i}:\n\n{text}\n")

    def copy_to_clipboard():
        tk_view.clipboard_clear()
        tk_view.clipboard_append(text_box.get(1.0, END))
        tk_view.update()

    button_copy = Button(tk_view, text="Copy", command=copy_to_clipboard)
    button_copy.pack()

def main_screen():
    global tk
    global text1
    global generated_key

    generated_key = ""
    saved_texts.clear()
    
    tk = Tk()
    tk.geometry("1024x400")

    image_icon = PhotoImage(file="locked.png")
    tk.iconphoto(False, image_icon)
    tk.title("Encrypted Notepad")

    def resetText():
        text1.delete(1.0, END)

    Label(text="Enter the notes here:", fg="black", font=("Roboto", 12)).place(x=15, y=20)
    text1 = Text(font="Roboto", bg="white", relief=GROOVE, wrap=WORD, bd=2)
    text1.place(x=20, y=60, width=880, height=200)

    global button_encrypt, button_decrypt, button_viewSave
    button_encrypt = Button(text="Encrypt", height="2", width=25, bg="#FFFFFF", fg="black", bd=2, command=encrypt)
    button_encrypt.place(x=20, y=300)
    button_decrypt = Button(text="Decrypt", height="2", width=25, bg="#FFFFFF", fg="black", bd=2, command=decrypt)
    button_decrypt.place(x=220, y=300)
    button_viewSave = Button(text="View saved notes", height="2", width=25, bg="#FFFFFF", fg="black", bd=2, command=view_saved_texts)
    button_viewSave.place(x=420, y=300)

    button_reset = Button(text="Reset", height="2", width=25, bg="#FFFFFF", fg="black", bd=2, command=resetText)
    button_reset.place(x=20, y=350)
    button_saveFile = Button(text="Open a Text File", height="2", width=25, bg="#FFFFFF", fg="black", bd=2,
                             command=open_text_file)
    button_saveFile.place(x=220, y=350)

    tk.mainloop()

main_screen()
