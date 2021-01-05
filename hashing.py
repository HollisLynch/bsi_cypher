import hashlib
from binascii import hexlify
import secrets

data = input("Enter message: ")
data = str.encode(data)
salt = secrets.token_bytes(32)

sha3_512 = hashlib.sha3_512(data)
sha3_512_digest = sha3_512.digest()
sha3_512_hex_digest = sha3_512.hexdigest()

hashed_message_salt = hashlib.sha512(data + salt).hexdigest()

print('Printing digest output')
print(sha3_512_digest)
print('Printing hexadecimal output')
print(sha3_512_hex_digest)
print('Printing salt')
print(hashed_message_salt)
