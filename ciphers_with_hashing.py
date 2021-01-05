from Crypto.Cipher import DES, Blowfish, AES
from Crypto import Random
from Crypto.PublicKey import ElGamal, RSA
from Crypto.Util.number import GCD
from Crypto import Random
from Crypto.Random import random
from Crypto.Cipher import PKCS1_OAEP
import base64

def elgamal(message):
    """
    Randomly generate a fresh, new ElGamal key.
    The key will be safe for use for both encryption and signature.
    """
    key = ElGamal.generate(1024, Random.new().read)
    while 1:
        k = random.StrongRandom().randint(1, key.p - 1)
        
        if GCD(k, key.p - 1) == 1:
            break
    """Encrypts and decrypts the message"""
    e = key.encrypt(message, k)
    d = key.decrypt(e)

    print('encrypted message: {}'.format(e))
    print('decrypted message: {}'.format(d))

def rsa(message):
    """
    Generating new keys
        Generating a keypair may take a long time, depending on the number of bits required. 
        The number of bits determines the cryptographic strength of the key, as well as the size of the message you can encrypt.
    """
    key = RSA.generate(2048)
    private_key = key.exportKey('PEM')
    public_key = key.publickey().exportKey('PEM')
    """ Encrypting message using public key """
    rsa_public_key = RSA.importKey(public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    encrypted_text = rsa_public_key.encrypt(message)
    encrypted_text_b64 = base64.b64encode(encrypted_text)

    print('encrypted message: {}'.format(encrypted_text_b64))
    """ Decrypting message using private key """
    rsa_private_key = RSA.importKey(private_key)
    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    decrypted_text = rsa_private_key.decrypt(encrypted_text)

    print('decrypted message: {}'.format(decrypted_text))

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


print("Choose algorithm:\n1 - aes\n2 - des\n3 - blowfish\n4 - elgamal\n5 - rsa")
choose = int(input())

message = input('Message:')
message = str.encode(message)

if choose == 1:
    aes(message)
if choose == 2:
    des(message)
if choose == 3:
    blowfish(message)
if choose == 4:
    elgamal(message)
if choose == 5:
    rsa(message)
