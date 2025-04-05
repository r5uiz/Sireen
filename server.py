import socket
import threading
import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import hashlib
import atexit

class SecureChatServer:
    def _init_(self, host='0.0.0.0', port=12346):
        """تهيئة خادم الدردشة الآمنة"""
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}
        self.public_key, self.private_key = rsa.newkeys(2048)
        
        # إعدادات إضافية للتحكم في المنفذ
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        atexit.register(self.cleanup)
        
    def start(self):
        """بدء تشغيل الخادم"""
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"Server started on {self.host}:{self.port}")
            
            while True:
                client_socket, addr = self.server_socket.accept()
                print(f"New connection from {addr}")
                threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, addr),
                    daemon=True
                ).start()
                
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.cleanup()
    
    def handle_client(self, client_socket, addr):
        """معالجة اتصال العميل"""
        try:
            # إرسال المفتاح العام للخادم إلى العميل
            client_socket.send(self.public_key.save_pkcs1())
            
            # استقبال المفتاح المتماثل المشفر من العميل
            encrypted_key = client_socket.recv(4096)
            symmetric_key = rsa.decrypt(encrypted_key, self.private_key)
            
            # إنشاء متجه تهيئة (IV)
            iv = os.urandom(16)
            client_socket.send(iv)
            
            # إنشاء كائن التشفير
            cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
            
            # إضافة العميل إلى القاموس
            self.clients[addr] = {
                'socket': client_socket,
                'cipher': cipher,
                'symmetric_key': symmetric_key
            }
            
            # بدء الدردشة
            while True:
                encrypted_msg = client_socket.recv(4096)
                if not encrypted_msg:
                    break
                    
                try:
                    decrypted_msg = unpad(
                        cipher.decrypt(encrypted_msg),
                        AES.block_size
                    ).decode('utf-8')
                    print(f"Client {addr}: {decrypted_msg}")
                    
                    # بث الرسالة إلى جميع العملاء
                    self.broadcast(decrypted_msg, addr)
                except Exception as e:
                    print(f"Decryption error: {e}")
                    
        except Exception as e:
            print(f"Error with client {addr}: {e}")
        finally:
            client_socket.close()
            if addr in self.clients:
                del self.clients[addr]
            print(f"Client {addr} disconnected")
    
    def broadcast(self, message, sender_addr):
        """بث الرسالة إلى جميع العملاء المتصلين"""
        for addr, client in self.clients.items():
            if addr != sender_addr:
                try:
                    # إنشاء IV جديد لكل رسالة (أفضل ممارسة أمنية)
                    iv = os.urandom(16)
                    client['socket'].send(iv)
                    cipher = AES.new(client['symmetric_key'], AES.MODE_CBC, iv)
                    
                    encrypted_msg = cipher.encrypt(
                        pad(message.encode('utf-8'), AES.block_size)
                    )
                    client['socket'].send(encrypted_msg)
                except Exception as e:
                    print(f"Error broadcasting to {addr}: {e}")

    def cleanup(self):
        """تنظيف الموارد عند الإغلاق"""
        print("Cleaning up server resources...")
        for client in self.clients.values():
            client['socket'].close()
        self.server_socket.close()
        print("Server shutdown complete")

if name == "main":
    server = SecureChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nServer stopped by user")