import socket
import sec_modules
import json

def handle_client(client_socket):
    try:
        # Generate RSA key pair for secure communication
        rsa_private_key, rsa_public_key = sec_modules.generate_rsa_keypair()
        
        # Send the RSA public key to the client
        serialized_public_key = rsa_public_key.public_bytes(
            encoding=sec_modules.serialization.Encoding.PEM,
            format=sec_modules.serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.sendall(serialized_public_key)

        # Receive the encrypted DES key from the client
        des_key_encrypted = client_socket.recv(1024)
        des_key = sec_modules.asymmetric_decrypt(
            rsa_private_key, des_key_encrypted, sec_modules.hashes.SHA256
        )

        while True:
            # Receive the command from the client
            command = client_socket.recv(1024).decode()
            if command == "exit":
                print("Client disconnected.")
                break

            elif command == "register":
                # Receive encrypted username and password
                encrypted_username = client_socket.recv(1024)
                encrypted_password = client_socket.recv(1024)

                username = sec_modules.symmetric_decrypt(des_key, encrypted_username, sec_modules.hashes.SHA256).decode()
                password = sec_modules.symmetric_decrypt(des_key, encrypted_password, sec_modules.hashes.SHA256).decode()
                sec_modules.store_user_credentials(username, password)

                # Register the user
                success = sec_modules.register(username, password)
                response = "success" if success else "failure"
                client_socket.sendall(response.encode())

            elif command == "authenticate":
                # Receive encrypted username and password
                encrypted_username = client_socket.recv(1024)
                encrypted_password = client_socket.recv(1024)
                username = sec_modules.symmetric_decrypt(des_key, encrypted_username, sec_modules.hashes.SHA256).decode()
                password = sec_modules.symmetric_decrypt(des_key, encrypted_password, sec_modules.hashes.SHA256).decode()

                # Authenticate the user
                success = sec_modules.authenticate(username, password)
                response = "success" if success else "failure"
                client_socket.sendall(response.encode())
            elif command == "message":
                # Receive encrypted message
                encrypted_message = client_socket.recv(1024)
                message = sec_modules.symmetric_decrypt(des_key, encrypted_message, sec_modules.hashes.SHA256).decode()
                integrity_check = sec_modules.check_integrity_sha256(message.encode(), encrypted_message)
                if integrity_check:
                    client_socket.sendall("success".encode())
                    print("Message received: ", message)
                else:
                    client_socket.sendall("failure".encode())
                    print("Integrity check failed. Message not received.")
                print(message)
                 

    except Exception as e:
        print(f"Error: {e}")

    finally:
        client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 12345))
    server_socket.listen(5)
    print("Server is listening on port 12345...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection accepted from {addr}")
        handle_client(client_socket)

if __name__ == "__main__":
    start_server()
