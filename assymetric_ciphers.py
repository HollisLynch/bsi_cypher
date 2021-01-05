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

print("1 - elgamal\n2 - rsa")
cipher = int(input())
message = input('plaintext:')
message = str.encode(message)
if cipher == 1:
    elgamal(message)
if cipher == 2:
    rsa(message)