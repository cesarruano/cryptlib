from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class Encrypter:
    def __init__(self, key=None, file=None):
        if key is not None:
            self.key = key
        elif file is not None:
            with open(file, "rb") as key_file:
                self.key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
        else:
            raise(ValueError("Invalid key source"))
    
    def encrypt(self, data):
        encrypted = self.key.encrypt(
        data,
        padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

class Decrypter:
    def __init__(self, key=None, file=None):
        if key is not None:
            self.key = key
        elif file is not None:
            with open(file, "rb") as key_file:
                self.key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        else:
            raise(ValueError("Invalid key source"))
    def decrypt(self, data):
        decrypted = self.key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted

class KeyManager:
    def __init__(self):
        pass
    
    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
        self.public_key = self.private_key.public_key()

        self.private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )    

        self.public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        
    def store_key(self, key, path):
        with open(path, 'wb') as f:
            f.write(key)
    
    def create_key_files(self, path):
        self.generate_keys()
        self.store_key(self.public_pem, path+"_pub.pem")
        self.store_key(self.private_pem, path+"_priv.pem")
        
    