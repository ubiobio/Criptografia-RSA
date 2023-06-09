#!/usr/bin/env python

# uso: decipher.py
#
# Descifrar mensajes (RSA)
#
# argumentos posicionales:
#   --public-key                    Llave RSA publica
#   --private-key                   Llave RSA privada
#
# argumentos opcionales:
#   -p                              Contraseña de la llave RSA privada
#
# pylint: disable=deprecated-module, unused-variable, missing-module-docstring, broad-exception-caught, too-many-locals
#

import sys
import optparse

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import serialization


def read_file(filename):
    """Leer un archivo.

    Argumentos:
    filename -- nombre del archivo
    """

    with open(filename, 'rb') as file:
        return file.read()


def decrypt_aes(encrypted_aes_key, private_key):
    """Desencriptar llave AES utilizando llave RSA privada.

    Argumentos:
    encrypted_aes_key -- llave AES encriptada
    private_key -- llave RSA privada
    """
    plaintext = private_key.decrypt(
        encrypted_aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def decrypt_ciphertext(ciphertext, aes_key, iv_vector):
    """Desencriptar mensaje encriptado con llave AES y vector IV.

    ciphertext -- texto cifrado
    aes_key -- llave AES
    iv -- vector IV
    """
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv_vector))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


def verify_signature(message, signature, public_key):
    """Verificar la firma del mensaje con una llave pública.

    message -- el mensaje
    signature -- la firma
    public_key -- llave RSA pública
    """
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
    """Descifrar un mensaje con llave RSA"""

    parser = optparse.OptionParser("%prog --public-key <path> --private-key <path> -p [password]")
    parser.add_option('--public-key', dest='public_key', type='string')
    parser.add_option('--private-key', dest='private_key', type='string')
    parser.add_option("-p", dest='password', type="string")
    options, arguments = parser.parse_args()

    if not options.public_key:
        parser.error("No se ingresó una llave pública.")
        parser.print_usage()
        sys.exit()

    if not options.private_key:
        parser.error("No se ingresó una llave privada.")
        parser.print_usage()
        sys.exit()

    if not options.password:
        options.password = None
    else:
        options.password = options.password.encode()

    message_filename = "decipher/ciphertext.txt"
    signature_filename = "decipher/signature.sig"
    iv_filename = "decipher/IV.iv"
    encrypted_aes_key_filename = "decipher/aes_key.enc"
    alice_public_key_filename = options.public_key
    bob_private_key_filename = options.private_key

    # Leer los archivos
    message = read_file(message_filename)
    signature = read_file(signature_filename)
    encrypted_aes_key = read_file(encrypted_aes_key_filename)
    iv_vector = read_file(iv_filename)

    # Cargar llave RSA pública
    with open(alice_public_key_filename, "rb") as key_file:
        alice_public_key = serialization.load_pem_public_key(
            key_file.read()
        )

    # Cargar llave RSA privada
    with open(bob_private_key_filename, "rb") as key_file:
        bob_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=options.password
        )

    try:
        # Descifrar llave AES cifrada con una llave privada
        aes_key = decrypt_aes(encrypted_aes_key, bob_private_key)

        # Descifrar texto cifrado con la llave AES
        plaintext = decrypt_ciphertext(message, aes_key, iv_vector)

        # Verificar la firma del mensaje
        verify_signature(plaintext, signature, alice_public_key)
        print("La firma es válida. El mensaje es genuino.")
        print("Contenido del mensaje:")
        print(plaintext.decode())
    except Exception as exception:
        print("La firma no es válida. El mensaje puede no ser genuino.")
        print("Error:", exception)


if __name__ == '__main__':
    main()
