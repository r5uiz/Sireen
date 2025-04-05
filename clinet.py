import os
import socket
import threading
import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

class SecureChatClient:
    def _init_(self, host='localhost', port=12346):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.symmetric_key = None
        self.cipher = None
        
    def connect(self):
        try:
            self.client_socket.connect((self.host, self.port))
            print(f"Connected to server at {self.host}:{self.port}")
            
            # Receive server's public key
            server_public_key = rsa.PublicKey.load_pkcs1(self.client_socket.recv(4096))
            
            # Generate symmetric key for AES
            self.symmetric_key = hashlib.sha256(os.urandom(32)).digest()

            
            # Encrypt symmetric key with server's public key
            encrypted_key = rsa.encrypt(self.symmetric_key, server_public_key)
            self.client_socket.send(encrypted_key)
            
            # Receive IV from server
            iv = self.client_socket.recv(16)
            self.cipher = AES.new(self.symmetric_key, AES.MODE_CBC, iv)
            
            # Start threads for sending and receiving messages
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.send_messages()
            
        except Exception as e:
            print(f"Connection error: {e}")
        finally:
            self.client_socket.close()
    
    def receive_messages(self):
        while True:
            try:
                # First receive IV for this message
                iv = self.client_socket.recv(16)
                cipher = AES.new(self.symmetric_key, AES.MODE_CBC, iv)
                
                encrypted_msg = self.client_socket.recv(4096)
                if not encrypted_msg:
                    break
                    
                decrypted_msg = unpad(cipher.decrypt(encrypted_msg), AES.block_size).decode('utf-8')
                print(f"\nReceived: {decrypted_msg}\nYou: ", end='')
            except Exception as e:
                print(f"\nError receiving message: {e}")
                break
    
    def send_messages(self):
        try:
            while True:
                message = input("You: ")
                if message.lower() == 'exit':
                    break
                
                # Generate new IV for each message (best practice)
                iv = os.urandom(16)
                self.client_socket.send(iv)
                cipher = AES.new(self.symmetric_key, AES.MODE_CBC, iv)
                
                encrypted_msg = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
                self.client_socket.send(encrypted_msg)
        except Exception as e:
            print(f"Error sending message: {e}")
        finally:
            self.client_socket.close()

if name == "main":
    client = SecureChatClient()
    client.connect()