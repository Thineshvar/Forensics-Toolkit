import hashlib
import tkinter as tk
from tkinter import filedialog, scrolledtext
from PIL import Image
from PIL.ExifTags import TAGS
from scapy.all import rdpcap
from cryptography.fernet import Fernet

# Initialize result_text globally
result_text = None

# Function to open the digital forensics toolkit
def open_toolkit():
    global result_text  # Access global variable
    toolkit_window = tk.Toplevel()
    toolkit_window.title("Digital Forensics Toolkit")

    # File Carving Button
    carve_button = tk.Button(toolkit_window, text="File Carving", command=carve_files)
    carve_button.pack(pady=5)

    # Metadata Analysis Button
    metadata_button = tk.Button(toolkit_window, text="Metadata Analysis", command=analyze_metadata)
    metadata_button.pack(pady=5)

    # Network Traffic Analysis Button
    traffic_button = tk.Button(toolkit_window, text="Network Traffic Analysis", command=analyze_traffic)
    traffic_button.pack(pady=5)

    # Hashing for File Integrity Button
    hash_button = tk.Button(toolkit_window, text="Hashing for File Integrity", command=hash_file)
    hash_button.pack(pady=5)

    # File Encryption Button
    encrypt_button = tk.Button(toolkit_window, text="Encrypt File", command=encrypt_file)
    encrypt_button.pack(pady=5)

    # File Decryption Button
    decrypt_button = tk.Button(toolkit_window, text="Decrypt File", command=decrypt_file)
    decrypt_button.pack(pady=5)

    # Result Display
    result_text = scrolledtext.ScrolledText(toolkit_window, width=60, height=20)
    result_text.pack(padx=10, pady=10)

# Function for File Carving
def carve_files():
    result_text.delete(1.0, tk.END)
    file_path = filedialog.askopenfilename(title="Select Disk Image", filetypes=[("Disk Images", "*.img")])
    if file_path:
        result_text.insert(tk.END, "File carving is not yet implemented.\n")

# Function for Metadata Analysis
def analyze_metadata():
    result_text.delete(1.0, tk.END)
    file_path = filedialog.askopenfilename(title="Select Image", filetypes=[("Images", "*.jpg *.jpeg *.png")])
    if file_path:
        try:
            image = Image.open(file_path)
            exif_data = image._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    result_text.insert(tk.END, f"{tag:25}: {value}\n")
            else:
                result_text.insert(tk.END, "No EXIF metadata found.\n")
        except Exception as e:
            result_text.insert(tk.END, f"Error analyzing metadata: {e}\n")

# Function for Network Traffic Analysis
def analyze_traffic():
    result_text.delete(1.0, tk.END)
    file_path = filedialog.askopenfilename(title="Select PCAP File", filetypes=[("PCAP Files", "*.pcap")])
    if file_path:
        try:
            packets = rdpcap(file_path)
            result_text.insert(tk.END, f"Total packets analyzed: {len(packets)}\n")
        except Exception as e:
            result_text.insert(tk.END, f"Error analyzing traffic: {e}\n")

# Function for Hashing for File Integrity
def hash_file():
    result_text.delete(1.0, tk.END)
    file_path = filedialog.askopenfilename(title="Select File")
    if file_path:
        try:
            with open(file_path, "rb") as file:
                file_content = file.read()
                hash_value = hashlib.sha256(file_content).hexdigest()
                result_text.insert(tk.END, f"SHA-256 Hash: {hash_value}\n")
        except Exception as e:
            result_text.insert(tk.END, f"Error hashing file: {e}\n")

# Function for File Encryption
def encrypt_file():
    result_text.delete(1.0, tk.END)
    file_path = filedialog.askopenfilename(title="Select File to Encrypt")
    if file_path:
        try:
            # Generate a key
            key = Fernet.generate_key()
            cipher_suite = Fernet(key)

            # Read file content
            with open(file_path, "rb") as file:
                file_data = file.read()

            # Encrypt file data
            encrypted_data = cipher_suite.encrypt(file_data)

            # Save the encrypted file
            encrypted_file_path = file_path + ".encrypted"
            with open(encrypted_file_path, "wb") as encrypted_file:
                encrypted_file.write(encrypted_data)

            # Save the key
            key_file_path = file_path + ".key"
            with open(key_file_path, "wb") as key_file:
                key_file.write(key)

            result_text.insert(tk.END, f"File encrypted successfully.\nEncrypted file saved as: {encrypted_file_path}\nKey saved as: {key_file_path}\n")
        except Exception as e:
            result_text.insert(tk.END, f"Error encrypting file: {e}\n")

# Function for File Decryption
def decrypt_file():
    result_text.delete(1.0, tk.END)
    encrypted_file_path = filedialog.askopenfilename(title="Select Encrypted File", filetypes=[("Encrypted Files", "*.encrypted")])
    if encrypted_file_path:
        key_file_path = filedialog.askopenfilename(title="Select Key File", filetypes=[("Key Files", "*.key")])
        if key_file_path:
            try:
                # Read the encryption key
                with open(key_file_path, "rb") as key_file:
                    key = key_file.read()
                cipher_suite = Fernet(key)

                # Read encrypted file content
                with open(encrypted_file_path, "rb") as encrypted_file:
                    encrypted_data = encrypted_file.read()

                # Decrypt the file data
                decrypted_data = cipher_suite.decrypt(encrypted_data)

                # Save the decrypted file
                decrypted_file_path = encrypted_file_path.replace(".encrypted", ".decrypted")
                with open(decrypted_file_path, "wb") as decrypted_file:
                    decrypted_file.write(decrypted_data)

                result_text.insert(tk.END, f"File decrypted successfully.\nDecrypted file saved as: {decrypted_file_path}\n")
            except Exception as e:
                result_text.insert(tk.END, f"Decryption failed: {e}\n")
        else:
            result_text.insert(tk.END, "No key file selected.\n")

# Example usage
if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    open_toolkit()
    root.mainloop()
