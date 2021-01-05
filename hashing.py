import hashlib
from binascii import hexlify

data = input("Enter message: ")
data = str.encode(data)

sha3_512 = hashlib.sha3_512(data)
sha3_512_digest = sha3_512.digest()
sha3_512_hex_digest = sha3_512.hexdigest()

print('Printing digest output')
print(sha3_512_digest)
print('Printing hexadecimal output')
print(sha3_512_hex_digest)
