import sec_modules
import socket
import serialization
import json



def connect_to_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 12345))
    return s



def main():
    s = connect_to_server()
    deskey = sec_modules.generate_des_key()
    RSAPublicKey = s.recv(1024)
    decodedPublicKey = RSAPublicKey.decode('utf-8')
    desKeyEncrypted = sec_modules.asymmetric_encrypt(decodedPublicKey, deskey, sec_modules.hash_data_sha256)
    s.sendall(desKeyEncrypted.encode('utf-8'))
    while True:
        command = input("Enter a command: ")
        if command == "exit":
            s.sendall(command.encode())
            break
        elif command == "register":
            username = input("Enter username: ")
            password = input("Enter password: ")
            encryptedUsername = sec_modules.symmetric_encrypt(username, deskey, sec_modules.hash_data_sha256)
            encryptedPassword = sec_modules.symmetric_encrypt(password, deskey, sec_modules.hash_data_sha256)
            s.sendall(encryptedUsername.encode())
            s.sendall(encryptedPassword.encode())
            response = s.recv(1024).decode()
            if response == "success":
                print("Registration successful.")
            else:
                print("Registration failed.")
        elif command == "authenticate":
            username = input("Enter username: ")
            password = input("Enter password: ")
            encryptedUsername = sec_modules.symmetric_encrypt(username, deskey, sec_modules.hash_data_sha256)
            encryptedPassword = sec_modules.symmetric_encrypt(password, deskey, sec_modules.hash_data_sha256)
            s.sendall(encryptedUsername.encode())
            s.sendall(encryptedPassword.encode())
            response = s.recv(1024).decode()
            if response == "success":
                print("Authentication successful.")
            else:
                print("Authentication failed.")
        elif command == "message":
            message = input("Enter message: ")
            encryptedMessage = sec_modules.symmetric_encrypt(message, deskey, sec_modules.hash_data_sha256)
            s.sendall(encryptedMessage.encode())
            response = s.recv(1024).decode()
            if response == "success":
                print("Message sent successfully.")
            elif response == "failure":
                print("Message was corrupted.")
            else:
                print("Message failed to send.")

