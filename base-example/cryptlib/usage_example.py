import encryption_lib



#encryption_lib.create_key_files()

#pub = encryption_lib.read_public_key("./public_key.pem")
#priv = encryption_lib.read_private_key("./private_key.pem")


km = encryption_lib.KeyManager()
km.create_key_files("./example1")

enc = encryption_lib.Encrypter(file="./example1_pub.pem")
dec = encryption_lib.Decrypter(file="./example1_priv.pem")

data = b'129-231nsd01'

encrypted_data = enc.encrypt(data)
decrypted_data = dec.decrypt(encrypted_data)

print(data)
print(encrypted_data)
print(decrypted_data)
