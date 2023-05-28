#!/usr/bin/env python

# uso: keygen.py
#
# Generar par de llaves RSA
#

import sys
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def rsa_private_key(public_exponent=65537, key_size=2048):
    """Generar llave RSA.

    Argumentos:
    public_exponent -- Propiedad matemática de la generación de la llave (default 65537)
    key_size -- Tamaño de la llave en bits (default 2048)
    """

    return rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )


def main():
    """Función principal.

    - Codificación de serialización: PEM
    - Formato privado: PKCS8
    - Contraseña (opcional): BestAvailableEncryption
    """

    DEFAULT_KEY_FILE = "id_rsa"
    MAX_PASSPHRASE_ATTEMPTS = 5

    print("Generando par de llaves RSA pública/privada.")
    key_file = input(f"Ingresa el archivo en donde deseas guardar la llave ({os.path.join(os.getcwd(), DEFAULT_KEY_FILE)}): ")
    if not key_file:
        key_file = DEFAULT_KEY_FILE

    passphrase = ""
    attempts = MAX_PASSPHRASE_ATTEMPTS
    while attempts:
        passphrase = input(f"Ingresa una contraseña (vacío para sin contraseña): ")
        passphrase_confirm = input(f"Ingresa la misma contraseña otra vez: ")
        if passphrase == passphrase_confirm:
            break

        attempts -= 1
        if not attempts:
            print("Demasiados intentos fallidos. Intenta nuevamente.")
            exit(0)

        print("Las contraseñas no coinciden.")

    private_key = rsa_private_key()
    public_key = private_key.public_key()

    if passphrase:
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
        )
    else:
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    with open(f"{key_file}.pem", "w") as private_file:
        print("{}".format(private_pem.decode()), file=private_file)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(f"{key_file}.pub", "w") as public_file:
        print("{}".format(public_pem.decode()), file=public_file)

    print("Llaves generadas con éxito!")


if __name__ == '__main__':
    main()
