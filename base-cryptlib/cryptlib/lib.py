from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

class ShortEncrypter:
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

class ShortDecrypter:
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

class LongEncrypter:
    def __init__(self, asym_encrypter):
        self.asym_encrypter = asym_encrypter
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)

    def encrypt(self, long_data):
        heading = self.asym_encrypter.encrypt(self.key)
        encrypted_long_data = self.fernet.encrypt(long_data)
        print("len header: "+str(len(heading)))
        print("len encrypted_long_data: "+str(len(encrypted_long_data)))
        return heading+encrypted_long_data

class LongDecrypter:
    def __init__(self, asym_decrypter):
        self.asym_decrypter = asym_decrypter

    def decrypt(self, long_data):
        heading = long_data[:256]
        message = long_data[256:]
        print("len long_data: "+str(len(long_data)))
        print("len header: "+str(len(heading)))
        print("len message: "+str(len(message)))
        sym_key = Fernet(self.asym_decrypter.decrypt(heading))
        decrypted_message = sym_key.decrypt(message)
        return decrypted_message

class Encrypter:
    def __init__(self, key=None, file=None):
        self.short_encrypter = ShortEncrypter(key=key, file=file)
        self.long_encrypter = LongEncrypter(self.short_encrypter)
    
    def encrypt(self, data):
        return self.long_encrypter.encrypt(data)
        
    
class Decrypter:
    def __init__(self, key=None, file=None):
        self.short_decrypter = ShortDecrypter(key=key, file=file)
        self.long_decrypter = LongDecrypter(self.short_decrypter)
    
    def decrypt(self, data):
        return self.long_decrypter.decrypt(data)
        

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
        
    