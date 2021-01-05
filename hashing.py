import hashlib
from binascii import hexlify
import scrypt, secrets

password = b'not a number'
salt = secrets.token_bytes(32)
scrypt_key = scrypt.hash(password, salt, N=16384, r=8, p=1, 32)
print('Salt: ', salt)
print('Key: ', scrypt_key)

data = input("Enter message: ")
data = str.encode(data)

sha3_512 = hashlib.sha3_512(data)
sha3_512_digest = sha3_512.digest()
sha3_512_hex_digest = sha3_512.hexdigest()

print('Printing digest output')
print(sha3_512_digest)
print('Printing hexadecimal output')
print(sha3_512_hex_digest)
