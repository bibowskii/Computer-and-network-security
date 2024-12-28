import os
import hashlib
import json
import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

USER_CREDENTIALS_FILE = "user_credentials.json"  # Path to the file where user credentials will be stored
KEY_STORAGE_FILE = "keys.json"  # Path to the file where keys will be stored

def register(username, password):
    # Check if the user credentials file exists
    if not os.path.exists(USER_CREDENTIALS_FILE):
        # Create the user credentials file with an empty JSON object
        with open(USER_CREDENTIALS_FILE, "w") as f:
            json.dump({}, f)
    
    # Load existing user credentials
    user_credentials = load_user_credentials()
    
    # Check if the username already exists
    if username in user_credentials:
        print("Username already exists. Please choose a different username.")
        return False
    
    # Hash the password before storing it
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Store the username and password hash
    user_credentials[username] = password_hash.decode('utf-8')
    store_user_credentials(username=username, hashed_password_with_salt=user_credentials[username])
    print("Registration successful.")
    return True

def authenticate(username, password):
    user_credentials = load_user_credentials()
    if username in user_credentials:
        # Retrieve the hashed password from the database
        stored_password_hash = user_credentials[username]
        # Check if the provided password matches the stored hash
        if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
            print("Authentication successful.")
            return True
        else:
            print("Incorrect password.")
            return False
    else:
        print("User not found.")
        return False

def hash_password(password, salt):
    # Hash the password with the provided salt using SHA-256
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    # Return the hashed password as bytes
    return hashed_password

def store_user_credentials(username, hashed_password_with_salt):
    # Load existing user credentials
    user_credentials = load_user_credentials()
    # Store the username, hashed password, and salt
    user_credentials[username] = hashed_password_with_salt
    with open(USER_CREDENTIALS_FILE, "w") as f:
        json.dump(user_credentials, f)
    print("User credentials stored successfully.")

def load_user_credentials():
    if os.path.exists(USER_CREDENTIALS_FILE):
        with open(USER_CREDENTIALS_FILE, "r") as f:
            return json.load(f)
    else:
        return {}

def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def asymmetric_sign(private_key, data):
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature

def asymmetric_verify(public_key, signature, data):
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def generate_aes_key():
    # Generate a random AES key
    return os.urandom(32)  # 32 bytes for AES-256

def generate_des_key():
    # Generate a random DES key
    return os.urandom(8)  # 8 bytes for DES

def symmetric_encrypt(key, plaintext, algorithm):
    backend = default_backend()
    cipher = Cipher(algorithm(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithm.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def symmetric_decrypt(key, ciphertext, algorithm):
    backend = default_backend()
    cipher = Cipher(algorithm(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithm.block_size).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def asymmetric_encrypt(public_key, plaintext, algorithm):
    ciphertext = public_key.encrypt(
        plaintext,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=algorithm()),
            algorithm=algorithm(),
            label=None
        )
    )
    return ciphertext

def asymmetric_decrypt(private_key, ciphertext, algorithm):
    plaintext = private_key.decrypt(
        ciphertext,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=algorithm()),
            algorithm=algorithm(),
            label=None
        )
    )
    return plaintext

def hash_data(data):
    backend = default_backend()
    digest = hashes.Hash(hashes.MD5(), backend=backend)
    digest.update(data)
    hashed_data = digest.finalize()
    return hashed_data

def hash_data_sha256(data):
    backend = default_backend()
    digest = hashes.Hash(hashes.SHA256(), backend=backend)
    digest.update(data)
    hashed_data = digest.finalize()
    return hashed_data

def check_integrity(data, expected_hash):
    computed_hash = hash_data(data)
    return computed_hash == expected_hash

def check_integrity_sha256(data, expected_hash):
    computed_hash = hash_data_sha256(data)
    return computed_hash == expected_hash

def store_key(key_name, key):
    # Store key securely (you might want to encrypt it before storing)
    key_storage = {}
    if os.path.exists(KEY_STORAGE_FILE):
        with open(KEY_STORAGE_FILE, "r") as f:
            key_storage = json.load(f)
    
    if isinstance(key, rsa.RSAPublicKey):
        key_data = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    elif isinstance(key, rsa.RSAPrivateKey):
        key_data = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    else:
        key_data = key.hex()
    
    key_storage[key_name] = key_data
    with open(KEY_STORAGE_FILE, "w") as f:
        json.dump(key_storage, f)

def load_key(key_name):
    # Load key securely (you might want to decrypt it after loading)
    if os.path.exists(KEY_STORAGE_FILE):
        with open(KEY_STORAGE_FILE, "r") as f:
            key_storage = json.load(f)
        if key_name in key_storage:
            key_data = key_storage[key_name]
            if 'PUBLIC' in key_data:  # Assuming RSA public key stored as 'PUBLIC' string
                return serialization.load_pem_public_key(
                    key_data.encode('utf-8'),
                    backend=default_backend()
                )
            elif 'PRIVATE' in key_data:  # Assuming RSA private key stored as 'PRIVATE' string
                return serialization.load_pem_private_key(
                    key_data.encode('utf-8'),
                    password=None,  # Assuming no password protection
                    backend=default_backend()
                )
            else:
                return bytes.fromhex(key_data)
    return None

def store_ecc_key(key_name, private_key, public_key):
    # Store ECC keys securely
    key_storage = {}
    if os.path.exists(KEY_STORAGE_FILE):
        with open(KEY_STORAGE_FILE, "r") as f:
            key_storage = json.load(f)
    
    key_storage[key_name + "_private"] = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    key_storage[key_name + "_public"] = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    with open(KEY_STORAGE_FILE, "w") as f:
        json.dump(key_storage, f)

def load_ecc_key(key_name):
    # Load ECC keys securely
    if os.path.exists(KEY_STORAGE_FILE):
        with open(KEY_STORAGE_FILE, "r") as f:
            key_storage = json.load(f)
        private_key_pem = key_storage.get(key_name + "_private")
        public_key_pem = key_storage.get(key_name + "_public")
        
        if private_key_pem and public_key_pem:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            return private_key, public_key
    return None, None

if __name__ == "__main__":
    authenticated = False
    print("Welcome to the Authentication System")
    print("1. Register a new user")
    print("2. Log in")
    choice = input("Enter your choice (1 or 2): ")
    
    if choice == "1":
        username = input("Enter username: ")
        password = input("Enter password: ")
        authenticated = register(username, password)
    elif choice == "2":
        username = input("Enter username: ")
        password = input("Enter password: ")
        authenticated = authenticate(username, password)
    else:
        print("Invalid choice.")
    
    if authenticated:
        # Symmetric encryption and decryption using AES
        plaintext = b'This is a secret message.'
        print("-" * 60)
        
        # Generate AES key
        aes_key = generate_aes_key()
        # Store keys
        store_key('aes-key', aes_key)
        print("Stored AES-Key..")
        # Load keys
        loaded_aes_key = load_key('aes-key')
        
        ciphertext = symmetric_encrypt(loaded_aes_key, plaintext, algorithms.AES)
        decrypted_text = symmetric_decrypt(loaded_aes_key, ciphertext, algorithms.AES)
        print("Symmetric Encryption-Decryption using AES:")
        print("Plaintext:", plaintext)
        print("Ciphertext:", ciphertext)
        print("Decrypted Text:", decrypted_text)
        print("-" * 60)
        
        # Generate DES key
        des_key = generate_des_key()
        # Store keys
        store_key('des-key', des_key)
        print("Stored DES-Key..")
        # Load keys
        loaded_des_key = load_key('des-key')
        
        # Symmetric encryption and decryption using DES
        ciphertext_des = symmetric_encrypt(loaded_des_key, plaintext, algorithms.TripleDES)
        decrypted_text_des = symmetric_decrypt(loaded_des_key, ciphertext_des, algorithms.TripleDES)
        print("Symmetric Encryption-Decryption using DES:")
        print("Plaintext:", plaintext)
        print("Ciphertext:", ciphertext_des)
        print("Decrypted Text:", decrypted_text_des)
        print("-" * 60)
        
        # Generate RSA key pair
        private_key_rsa, public_key_rsa = generate_rsa_keypair()
        # Store keys
        store_key('public-rsa-key', public_key_rsa)
        store_key('private-rsa-key', private_key_rsa)
        print("Stored public-rsa-key..")
        print("Stored private-rsa-key..")
        # Load keys
        loaded_public_rsa_key = load_key('public-rsa-key')
        loaded_private_rsa_key = load_key('private-rsa-key')
        
        # Asymmetric encryption and decryption using RSA
        ciphertext_rsa = asymmetric_encrypt(loaded_public_rsa_key, plaintext, hashes.SHA256)
        decrypted_text_rsa = asymmetric_decrypt(loaded_private_rsa_key, ciphertext_rsa, hashes.SHA256)
        print("Asymmetric Encryption-Decryption using RSA:")
        print("Plaintext:", plaintext)
        print("Ciphertext:", ciphertext_rsa)
        print("Decrypted Text:", decrypted_text_rsa)
        print("-" * 60)
        
        # Hashing using MD5
        hashed_data = hash_data(plaintext)
        print("Hashing using MD5:")
        print("Data:", plaintext)
        print("Hashed Data:", hashed_data)
        
        # Check integrity
        print("Checking Integrity for the decrypted message using MD5:")
        data_to_check = decrypted_text
        expected_hash = hashed_data
        is_integrity_valid = check_integrity(data_to_check, expected_hash)
        print("Integrity Valid:", is_integrity_valid)
        print("-" * 60)
        
        # Hashing using SHA-256
        hashed_data_sha256 = hash_data_sha256(plaintext)
        print("Hashing using SHA-256:")
        print("Data:", plaintext)
        # Hashing using SHA-256
        hashed_data_sha256 = hash_data_sha256(plaintext)
        print("Hashing using SHA-256:")
        print("Data:", plaintext)
        print("Hashed Data (SHA-256):", hashed_data_sha256)
        
        # Check integrity
        print("Checking Integrity for the decrypted message using SHA256:")
        data_to_check_SHA256 = decrypted_text
        expected_hash_SHA256 = hashed_data_sha256
        is_integrity_valid = check_integrity_sha256(data_to_check_SHA256, expected_hash_SHA256)
        print("Integrity Valid:", is_integrity_valid)
        print("-" * 60)
        
        # Generate ECC key pairs for sender and receiver
        private_key_sender, public_key_sender = generate_ecc_keypair()
        private_key_receiver, public_key_receiver = generate_ecc_keypair()
        
        # Store keys
        store_ecc_key('sender-ecc-keys', private_key_sender, public_key_sender)
        store_ecc_key('receiver-ecc-keys', private_key_receiver, public_key_receiver)
        print("Stored sender-ecc-keys..")
        print("Stored receiver-ecc-keys..")
        
        # Load keys
        loaded_private_key_sender, loaded_public_key_sender = load_ecc_key('sender-ecc-keys')
        loaded_private_key_receiver, loaded_public_key_receiver = load_ecc_key('receiver-ecc-keys')
        
        # Key exchange
        shared_key_sender = private_key_sender.exchange(ec.ECDH(), loaded_public_key_receiver)
        shared_key_receiver = private_key_receiver.exchange(ec.ECDH(), loaded_public_key_sender)
        
        # Use the shared key for symmetric encryption
        plaintext = b'Some confidential information using ECC for key exchange.'
        ciphertext = symmetric_encrypt(shared_key_sender, plaintext, algorithms.AES)
        decrypted_text = symmetric_decrypt(shared_key_receiver, ciphertext, algorithms.AES)
        
        print("Hybrid Encryption-Decryption (ECC for key exchange, AES for encryption):")
        print('Shared Key for Receiver:', shared_key_receiver)
        print('Shared Key for Sender:', shared_key_sender)
        print("Plaintext:", plaintext)
        print("Ciphertext:", ciphertext)
        print("Decrypted Text:", decrypted_text.decode())
    else:
        print("Not Authorized to continue")
        