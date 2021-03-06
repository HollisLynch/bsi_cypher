from Crypto.Cipher import DES, Blowfish, AES
from Crypto import Random

def blowfish(plaintext):
    '''
    The initialization vector to use for encryption or decryption.
    Create a new Blowfish cipher with Cipher FeedBack.
    CFB transforms the underlying block cipher into a stream cipher.
    When encrypting, each ciphertext segment contributes to the encryption of the next plaintext segment.
    '''
    iv = Random.new().read(Blowfish.block_size)

    print("1 - encypt\n2 - decrypt")
    choice = int(input())

    if choice == 1:
        print("key: ")
        key = str(input())
        blowfish_encrypt = Blowfish.new(key, Blowfish.MODE_CFB, iv)
        blowfish_decrypt = Blowfish.new(key, Blowfish.MODE_CFB, iv)

        encrypted = blowfish_encrypt.encrypt(plaintext)
        print(f"encrypted: {encrypted}")
        print("Decrypt?")
        i = str(input())
        if i == "yes":
            decrypted = blowfish_decrypt.decrypt(encrypted)
            print(decrypted)
        return encrypted
    if choice == 2:
        print("key: ")
        key = str(input())
        blowfish_decrypt = Blowfish.new(key, Blowfish.MODE_CFB, iv)
        decrypted = blowfish_decrypt.decrypt(plaintext)
        print(f"decrypted: {decrypted}")
        return decrypted

def aes(plaintext):
    """
    iv_AES (byte string) - The initialization vector to use for encryption or decryption.
    Create a new AES cipher.
    CFB is a mode of operation which turns the block cipher into a stream cipher.
    """
    iv_AES = Random.new().read(AES.block_size)

    print("1 - encypt\n2 - decrypt")
    choice = int(input())

    if choice == 1:
        key = b'Sixteen byte key'
        aes_encrypt = AES.new(key, AES.MODE_CFB, iv_AES)
        aes_decrypt = AES.new(key, AES.MODE_CFB, iv_AES)
        encrypted = aes_encrypt.encrypt(plaintext)
        print(f"encrypted: {encrypted}")
        print("Decrypt?")
        i = str(input())
        if i == "yes":
            decrypted = aes_decrypt.decrypt(encrypted)
            print(decrypted)
        return encrypted
    if choice == 2:
        key = b'Sixteen byte key'
        aes_decrypt = AES.new(key, AES.MODE_CFB, iv_AES)
        decrypted = aes_decrypt.decrypt(plaintext)
        print(f"decrypted: {decrypted}")
        return decrypted


def des(plaintext):
    """
    iv_DES (byte string) - The initialization vector to use for encryption or decryption.
    Create a new DES cipher.
    Electronic Code Book (ECB). This is the simplest encryption mode.
    Each of the plaintext blocks is directly encrypted into a ciphertext block, independently of any other block.
    """
    iv_DES = Random.new().read(DES.block_size)

    print("1 - encypt\n2 - decrypt")
    choice = int(input())

    if choice == 1:
        key = b'hello123'
        des_encrypt = DES.new(key, DES.MODE_ECB, iv_DES)
        des_decrypt = DES.new(key, DES.MODE_ECB, iv_DES)
        encrypted = des_encrypt.encrypt(plaintext)
        print(f"encrypted: {encrypted}")
        print("Decrypt?")
        i = str(input())
        if i == "yes":
            decrypted = des_decrypt.decrypt(encrypted)
            print(decrypted)
        return encrypted
    if choice == 2:
        key = b'abcdefgh'
        des_decrypt = DES.new(key, DES.MODE_ECB, iv_DES)
        decrypted = des_decrypt.decrypt(plaintext)
        print(f"decrypted: {decrypted}")
        return decrypted


print("Choose algorithm:\n1 - aes\n2 - des\n3 - blowfish")
choose = int(input())

print("plaintext: ")
plaintext = str(input())

if choose == 1:
    aes(plaintext)
if choose == 2:
    des(plaintext)
if choose == 3:
    blowfish(plaintext)

print(blowfish.__doc__)
