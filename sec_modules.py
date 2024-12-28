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


# Function to register a new user
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
    password_hash = bcrypt.hashpw(password.encode('utf-8'),
                                  bcrypt.gensalt())

    # Store the username and password hash
    user_credentials[username] = password_hash.decode('utf-8')
    store_user_credentials(username=username,
                           hashed_password_with_salt=user_credentials[username])

    print("Registration successful.")
    return True


def authenticate(username, password):
    user_credentials = load_user_credentials()
    if username in user_credentials:
        # Retrieve the hashed password from the database
        stored_password_hash = user_credentials[username]
        # Check if the provided password matches the stored hash
        if bcrypt.checkpw(password.encode('utf-8'),
                          stored_password_hash.encode('utf-8')):
            print("Authentication successful.")
            return True
        else:
            print("Incorrect password.")
            return False
    else:
        print("User not found.")
        return False

    # Function to hash a password using SHA-256 with salt


def hash_password(password, salt):
    # Hash the password with the provided salt using SHA-256
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf8'), salt, 100000)
    # Return the hashed password as bytes
    return hashed_password


# Function to store user credentials in a JSON file
def store_user_credentials(username, hashed_password_with_salt):
    # Load existing user credentials
    user_credentials = load_user_credentials()

    # Store the username, hashed password, and salt
    user_credentials[username] = hashed_password_with_salt
    with open(USER_CREDENTIALS_FILE, "w") as f:
        json.dump(user_credentials, f)

    print("User credentials stored successfully.")


# Function to load user credentials from the JSON file
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
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def asymmetric_encrypt(public_key, plaintext, algorithm):
    ciphertext = public_key.encrypt(plaintext,
                                    asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(algorithm=algorithm()),
                                                            algorithm=algorithm(), label=None))
    return ciphertext


def asymmetric_decrypt(private_key, ciphertext, algorithm):
    plaintext = private_key.decrypt(ciphertext,
                                    asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(algorithm=algorithm()),
                                                            algorithm=algorithm(), label=None))
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

