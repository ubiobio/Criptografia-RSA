#!/usr/bin/env python

# uso: decipher.py
#
# Descifrar mensajes (RSA)
#
# argumentos posicionales:
#   --public-key                    Llave RSA publica
#   --private-key                   Llave RSA privada
#

import optparse

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import serialization


def read_file(filename):
    with open(filename, 'rb') as file:
        return file.read()


def decrypt_rsa(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def decrypt_aes(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


def verify_signature(message, signature, public_key):
    public_key.verify(
        signature,
        message,
        asymmetric_padding.PSS(
            mgf=asymmetric_padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def main():
    """Descifrar un mensaje con llave RSA
    """

    p = optparse.OptionParser("%prog --public-key [path] --private-key [path]")
    p.add_option('--public-key', dest='public_key', type='string')
    p.add_option('--private-key', dest='private_key', type='string')
    options, arguments = p.parse_args()

    if not options.public_key:
        p.error("No se ingresó una llave pública.")
        p.print_usage()
        exit(0)

    if not options.private_key:
        p.error("No se ingresó una llave privada.")
        p.print_usage()
        exit(0)

    message_filename = "decipher/TextoCifrado.txt"
    signature_filename = "decipher/signature.sig"
    iv_filename = "decipher/IV.iv"
    encrypted_aes_key_filename = "decipher/llave_AES_cifrada.key"
    alice_public_key_filename = options.public_key  # Alice
    bob_private_key_filename = options.private_key  # Bob

    # Leer los archivos
    message = read_file(message_filename)
    signature = read_file(signature_filename)
    encrypted_aes_key = read_file(encrypted_aes_key_filename)
    iv = read_file(iv_filename)

    # Cargar llaves
    with open(alice_public_key_filename, "rb") as key_file:
        alice_public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    with open(bob_private_key_filename, "rb") as key_file:
        bob_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    # Descifrar la llave AES cifrada con la llave privada de Bob
    aes_key = decrypt_rsa(encrypted_aes_key, bob_private_key)

    # Descifrar el texto cifrado de Alice con la llave AES
    plaintext = decrypt_aes(message, aes_key, iv)

    try:
        # Verificar la firma del mensaje
        verify_signature(plaintext, signature, alice_public_key)
        print("La firma es válida. El mensaje es genuino.")
        print("Contenido del mensaje:")
        print(plaintext.decode())
    except Exception as e:
        print("La firma no es válida. El mensaje puede no ser genuino.")
        print("Error:", e)


if __name__ == '__main__':
    main()
