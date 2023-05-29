#!/usr/bin/env python

# uso: cipher.py
#
# Cifrar mensajes (RSA)
#
# argumentos posicionales:
#   --private-key                   Llave RSA privada
#   --public-key                    Llave RSA publica
#

import os
import optparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


def read_private_key(file, password=None):
    """Lee una llave privada desde un archivo PEM.

    Argumentos:
    file -- archivo de la llave privada
    password -- contraseña de la llave privada (default: None)
    """
    with open(file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
            backend=default_backend()
        )

    return private_key


def read_public_key(file):
    """Lee una llave RSA pública.

    Argumentos:
    file -- archivo de la llave RSA pública
    """
    with open(file, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    return public_key


def encrypt_aes_key(aes_key, public_key):
    """Encripta una llave AES con una llave RSA pública.

    Argumentos:
    aes_key -- llave AES
    public_key -- llave RSA pública
    """
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key


def encrypt_text(text, key, iv):
    """Encripta texto plano utilizando una llave AES y el vector IV en modo CBC.

    Argumentos:
    text -- texto plano
    key -- llave AES
    iv -- vector IV
    """
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(text) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext


def sign_text(text, private_key):
    """Firma text plano utilizando una llave privada.

    Argumentos:
    text -- texto plano
    private_key -- llave RSA privada
    """
    signature = private_key.sign(
        text,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def main():
    """Cifrador RSA
    """

    p = optparse.OptionParser("%prog --private-key [path] --public-key [path]")
    p.add_option('--private-key', dest='private_key', type='string')
    p.add_option('--public-key', dest='public_key', type='string')
    options, arguments = p.parse_args()

    if not options.private_key:
        p.error("No se ingresó una llave privada.")
        p.print_usage()
        exit(0)

    if not options.public_key:
        p.error("No se ingresó una llave pública.")
        p.print_usage()
        exit(0)

    plaintext = input(f"Ingresa un mensaje para enviar: ").encode()
    private_key = read_private_key(options.private_key)
    public_key = read_public_key(options.public_key)

    signature = sign_text(plaintext, private_key)

    with open("cipher/signature.sig", "wb") as signature_file:
        signature_file.write(signature)

    # Generar llave AES y vector IV
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    # Cifrar el texto plano en modo CBC con AES
    ciphertext = encrypt_text(plaintext, aes_key, iv)

    # Escribir el texto cifrado en un archivo
    with open('cipher/ciphertext.txt', 'wb') as ciphertext_file:
        ciphertext_file.write(ciphertext)

    # Escribir el vector IV en un archivo
    with open('cipher/IV.iv', 'wb') as iv_file:
        iv_file.write(iv)

    # Cifrar la llave AES con la llave pública
    encrypted_key = encrypt_aes_key(aes_key, public_key)

    # Almacenar la llave AES cifrada
    with open('cipher/aes_key.enc', 'wb') as encrypted_key_file:
        encrypted_key_file.write(encrypted_key)


if __name__ == '__main__':
    main()
