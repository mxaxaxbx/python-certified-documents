# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import serialization
# import os



# with open('private.pem', 'rb') as key_file:
#     private_key = serialization.load_pem_private_key(
#         key_file.read(),
#         password=None,
#         backend=default_backend()
#     )

# key = os.urandom(32)
# nonce = os.urandom(16)

# bts = open("file.pdf", "rb").read()

# algorithm = algorithms.ChaCha20(key, nonce)
# cipher = Cipher(algorithm, mode=None)
# encryptor = cipher.encryptor()
# ct = encryptor.update(bts)

# decryptor = cipher.decryptor()
# file = decryptor.update(ct)

# # save file
# with open("file1.pdf", "wb") as f:
#     f.write(file)



# import hashlib

# with open("file.pdf", 'rb') as f:
#   h1 = hashlib.sha256(f.read()).digest()
#   print(h1)

# h2 = hashlib.sha256(open("file.pdf", 'rb').read()).digest()

# if h1 == h2:
#   print("OK")
