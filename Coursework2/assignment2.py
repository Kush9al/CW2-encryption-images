from cryptography.fernet import Fernet
from PIL import ImageTk, Image
import tkinter as tk
from tkinter import filedialog


class ImageEncryptor:
    def __init__(self):
        self.key = None
        self.filepath = None
        self.encrypted_filepath = None

    def generate_key(self):
        self.key = Fernet.generate_key()

    def load_key(self, filepath):
        with open(filepath, 'rb') as f:
            self.key = f.read()

    def save_key(self, filepath):
        with open(filepath, 'wb') as f:
            f.write(self.key)

    def encrypt(self, filepath):
        self.filepath = filepath
        with open(filepath, 'rb') as f:
            data = f.read()

        fernet = Fernet(self.key)
        encrypted_data = fernet.encrypt(data)

        self.encrypted_filepath = filepath + '.encrypted'
        with open(self.encrypted_filepath, 'wb') as f:
            f.write(encrypted_data)

    def decrypt(self, filepath):
        self.filepath = filepath
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()

        fernet = Fernet(self.key)
        decrypted_data = fernet.decrypt(encrypted_data)

        self.encrypted_filepath = filepath.replace('.encrypted', '')
        with open(self.encrypted_filepath, 'wb') as f:
            f.write(decrypted_data)



class ImageEncryptorGUI:
    def __init__(self, master):
        self.master = master
        self.master.title('Image Encryptor')
        self.master.geometry('800x600')

        self.lbl_filepath = tk.Label(self.master, text='Filepath:')
        self.lbl_filepath.grid(row=0, column=0, padx=10, pady=10)

        self.txt_filepath = tk.Entry(self.master, width=50)
        self.txt_filepath.grid(row=0, column=1, padx=10, pady=10)

        self.btn_browse = tk.Button(self.master, text='Browse', command=self.browse_file)
        self.btn_browse.grid(row=0, column=2, padx=10, pady=10)

        self.lbl_key = tk.Label(self.master, text='Key:')
        self.lbl_key.grid(row=1, column=0, padx=10, pady=10)

        self.txt_key = tk.Entry(self.master, width=50, state='disabled')
        self.txt_key.grid(row=1, column=1, padx=10, pady=10)

        self.btn_generate_key = tk.Button(self.master, text='Generate Key', command=self.generate_key)
        self.btn_generate_key.grid(row=1, column=2, padx=10, pady=10)

        self.btn_load_key = tk.Button(self.master, text='Load Key', command=self.load_key)
        self.btn_load_key.grid(row=2, column=2, padx=10, pady=10)

        self.btn_save_key = tk.Button(self.master, text='Save Key', command=self.save_key, state='disabled')
        self.btn_save_key.grid(row=3, column=2, padx=10, pady=10)

        self.btn_encrypt = tk.Button(self.master, text='Encrypt', command=self.encrypt_file, state='disabled')
        self.btn_encrypt.grid(row=4, column=0, padx=10, pady=10)

        self.btn_decrypt = tk.Button(self.master, text='Decrypt', command=self.decrypt_file, state='disabled')
        self.btn_decrypt.grid(row=4, column=1, padx=10, pady=10)

        self.lbl_image = tk.Label(self.master)
        self.lbl_image.grid(row=5, column=0, columnspan=3, padx=10, pady=10)

    def browse_file(self):
        filepath = filedialog.askopenfilename()
        self.txt_filepath.delete(0, tk.END)
        self.txt_filepath.insert(0, filepath)

    def generate_key(self):
        self.encryption = ImageEncryptor()
        self.encryption.generate_key()
        self.txt_key.delete(0, tk.END)
        self.txt_key.insert(0, self.encryption.key.decode())
        self.btn_save_key['state'] = 'normal'
        self.btn_encrypt['state'] = 'normal'

    def load_key(self):
        filepath = filedialog.askopenfilename()
        self.encryption.load_key(filepath)
        self.txt_key.delete(0, tk.END)
        self.txt_key.insert(0, self.encryption.key.decode())
        self.btn_save_key['state'] = 'normal'
        self.btn_encrypt['state'] = 'normal'

    def save_key(self):
        filepath = filedialog.asksaveasfilename()
        self.encryption.save_key(filepath)

    def encrypt_file(self):
        filepath = self.txt_filepath.get()
        self.encryption.encrypt(filepath)
        self.show_image()

    def decrypt_file(self):
        filepath = self.txt_filepath.get()
        self.encryption.decrypt(filepath)
        self.show_image()

    def show_image(self):
        if self.encryption.encrypted_filepath:
            img = Image.open(self.encryption.encrypted_filepath)
            img = img.resize((500, 500), Image.ANTIALIAS)
            img_tk = ImageTk.PhotoImage(img)
            self.lbl_image.config(image=img_tk)
            self.lbl_image.image = img_tk
if __name__ == '__main__':
    root = tk.Tk()
    app = ImageEncryptorGUI(root)
    root.mainloop()

       
