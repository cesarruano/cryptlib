import lib as cryptlib
km = cryptlib.KeyManager()
km.create_key_files("./example1")
'''


enc = cryptlib.ShortEncrypter(file="./example1_pub.pem")
dec = cryptlib.ShortDecrypter(file="./example1_priv.pem")

data = b'129-231nsaasdewasdf;ksjdhfklashdfklasdlkfhqwerweqwqeewrd01'

encrypted_data = enc.encrypt(data)
decrypted_data = dec.decrypt(encrypted_data)

print(data)
print(encrypted_data)
print(decrypted_data)

print("Data lenght before rsa:" +str(len(data)))
print("Data lenght after rsa:" +str(len(encrypted_data)))

lenc = cryptlib.LongEncrypter(enc)
ldec = cryptlib.LongDecrypter(dec)

d = lenc.encrypt(data)
print(len(d))
dd = ldec.decrypt(d)
print(dd)
'''

enc = cryptlib.Encrypter(file="./example1_pub.pem")
dec = cryptlib.Decrypter(file="./example1_priv.pem")
data = b'129-231nsaasdewasdf;alsdjf;alsdflasdflaslkdfasdfkljasgdkfjaskdfkasdlfkjasdlkfhaskdjfaksjdhfklashdfklasdlkfhqwerweqwqeewrd01'
encrypted_data = enc.encrypt(data)
decrypted_data = dec.decrypt(encrypted_data)
print(data)
print(encrypted_data)
print(decrypted_data)