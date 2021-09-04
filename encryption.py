
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto import Random
from base64 import b64encode, b64decode
import rsa


hash_value = "SHA-256"


def new_keys(keysize):
    random_generator = Random.new().read
    key = RSA.generate(keysize, random_generator)
    private, public = key, key.publickey()
    return public, private


def import_key(extern_key):
    return RSA.import_key(extern_key)


def get_public_key(private_key):
    return private_key.publickey()


def encrypt(message, public_key):
    """
    RSA encryption protocol according to PKCS  1 OAEP
    """
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message)


def decrypt(ciphertext, private_key):
    """
    RSA encryption protocol according to PKCS  #1 OAEP
    """
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


def sign(message, private_key, hash_value_algorithm="SHA-256"):
    global hash_value
    hash_value = hash_value_algorithm

    sign_request = PKCS1_v1_5.new(private_key)

    if hash_value == "SHA-512":
        digest = SHA512.new()
    elif hash_value == "SHA-384":
        digest = SHA384.new()
    elif hash_value == "SHA-256":
        digest = SHA256.new()
    elif hash_value == "SHA-1":
        digest = SHA()
    else:
        digest = MD5()
    digest.update(message)
    return sign_request.sign(digest)


def verify(message, signature, public_key):

    verify_request = PKCS1_v1_5.new(public_key)

    if hash_value == "SHA-512":
        digest = SHA512.new()
    elif hash_value == "SHA-384":
        digest = SHA384.new()
    elif hash_value == "SHA-256":
        digest = SHA256.new()
    elif hash_value == "SHA-1":
        digest = SHA()
    else:
        digest = MD5()
    digest.update(message)
    return verify_request.verify(digest, signature)


def main_crypt_verification(msg1) -> None:

    key_size = 2048

    (public, private) = rsa.newkeys(key_size)

    # encodes the bytes-like object s as base64
    encrypted = b64encode(rsa.encrypt(msg1, public))
    # decodes the Base64 encoded bytes-like object or ASCII string s
    # returns the decoded bytes
    decrypted = rsa.decrypt(b64decode(encrypted), private)
    signature = b64encode(rsa.sign(msg1, private, "SHA-512"))

    verify = rsa.verify(msg1, b64decode(signature), public)

    print("Mensagem enviada pelo client: '%s'" % msg1)
    print("Encriptação: " + encrypted.decode('ascii'))
    print("Decriptação: '%s'" % decrypted)
    print("Assinatura de decriptação: " + signature.decode('ascii'))
    print("Verificação do tipo de hash: %s" % verify)
    rsa.verify(msg1, b64decode(signature), public)


if __name__ == "__main__":
    msg1 = b"MeNsAgEm EnViAdA"
    main_crypt_verification(msg1)
