from Crypto.Cipher import DES, Blowfish, AES
from Crypto import Random


def blowfish(plaintext):
    iv = Random.new().read(Blowfish.block_size)

    key = b'abcdefghijklmnop'

    blowfish_encrypt = Blowfish.new(key, Blowfish.MODE_CFB, iv)
    blowfish_decrypt = Blowfish.new(key, Blowfish.MODE_CFB, iv)

    encrypted = blowfish_encrypt.encrypt(plaintext)
    decrypted = blowfish_decrypt.decrypt(encrypted)

    print(encrypted)
    print(decrypted)
    return encrypted


def aes(plaintext):
    iv_AES = Random.new().read(AES.block_size)

    key_AES = b'abcdefghijklmnop'

    aes_encrypt = AES.new(key_AES, AES.MODE_CFB, iv_AES)
    aes_decrypt = AES.new(key_AES, AES.MODE_CFB, iv_AES)

    encrypted = aes_encrypt.encrypt(plaintext)
    decrypted = aes_decrypt.decrypt(encrypted)

    print(encrypted)
    print(decrypted)
    return encrypted


def des(plaintext):
    iv_DES = Random.get_random_bytes(8)

    key_DES = b'abcdefgh'

    des_encrypt = DES.new(key_DES, DES.MODE_CFB, iv_DES)
    des_decrypt = DES.new(key_DES, DES.MODE_CFB, iv_DES)

    encrypted = des_encrypt.encrypt(plaintext)
    decrypted = des_decrypt.decrypt(encrypted)

    print(encrypted)
    print(decrypted)
    return encrypted


print("plaintext: ")
plaintext = str(input())

print("Choose algorithm:")
print("1 - aes\n2 - des\n3 - blowfish")

choose = int(input())

if choose == 1:
    aes(plaintext)
if choose == 2:
    des(plaintext)
if choose == 3:
    blowfish(plaintext)
