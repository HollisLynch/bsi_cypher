from Crypto.PublicKey import ElGamal, RSA
from Crypto.Util.number import GCD
from Crypto import Random
from Crypto.Random import random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_OAEP
import base64


def elgamal(message):
    key = ElGamal.generate(1024, Random.new().read)
    hash = SHA.new(message).digest()

    obj = ElGamal.ElGamalobj.encrypt(message, key)
    print(obj)

def rsa(message):
    key = RSA.generate(2048)
    private_key = key.exportKey('PEM')
    public_key = key.publickey().exportKey('PEM')

    rsa_public_key = RSA.importKey(public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    encrypted_text = rsa_public_key.encrypt(message)
    encrypted_text_b64 = base64.b64encode(encrypted_text)

    print('encrypted message: {}'.format(encrypted_text_b64))

    rsa_private_key = RSA.importKey(private_key)
    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    decrypted_text = rsa_private_key.decrypt(encrypted_text)

    print('decrypted message: {}'.format(decrypted_text))


message = input('plaintext:')
message = str.encode(message)
elgamal(message)