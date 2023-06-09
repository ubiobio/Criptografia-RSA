#                             Criptografía-RSA
#
#   === Autores ===
#
#   José Benavente
#   Daniel Aguayo
#
#   El trabajo completo se encuentra versionado en GitHub:
#   https://github.com/ubiobio/Criptografia-RSA
#
#   === Descripción ===
#
#   Este es un proyecto para el electivo de Criptografía Aplicada, el cual
#   consiste en tres programas escritos en Python con el objetivo de implementar
#   la encriptación RSA en un contexto práctico.
#
#   === Uso ===
#
#   python keygen.py
#   python cipher.py --private-key llave_alice.pem --public-key llave_bob.pub -p [password]
#   python decipher.py --public-key llave_alice.pub --private-key llave_bob.pem -p [password]
#
#   === Explicación ===
#
#   Primero, ambos usuarios ejecutan el script keygen.py, el cual generará un
#   par de llaves RSA (pública y privada) para cada uno. Llamaremos a ambos
#   usuarios Alice y Bob para esta demostración.
#
#   Opcionalmente las llaves RSA pueden ser generadas con una contraseña. En caso
#   de ser así, para poder cifrar y descifrar mensajes Alice y Bob deberán pasar
#   sus contraseñas como el argumento -p a los scripts de cipher.py y decipher.py
#
#   Luego de generar las llaves, ambos usuarios intercambian llaves públicas.
#   Alice le envía su llave pública a Bob, y viceversa.
#
#   Después de generar las llaves y hacer el intercambio de las públicas, Alice
#   puede encriptar un mensaje utilizando el script cipher.py, pasando su
#   llave privada y la llave pública de Bob como argumentos.
#
#   Una vez encriptado el mensaje, se generarán varios archivos en el directorio
#   cipher/: aes_key.enc, ciphertext.txt, IV.iv y signature.sig. Estos archivos
#   deberán ser enviados a Bob para que este, con su llave privada, pueda
#   desencritpar el mensaje encriptado por Alice.
#
#   Para desencriptar el mensaje, Bob puede usar el script decipher.py, pasando la
#   llave pública de Alice y su llave privada como argumentos. Los archivos
#   originalmente generados por Alice deben encontrarse en el directorio decipher/
#   de Bob antes de proceder con la desencriptación.
#
#   Una vez ejecutado el script decipher.py, Bob podrá ver el mensaje en pantalla.
#   Si el mensaje no fue alterado, entonces el script entregará el contenido en
#   texto plano para que Bob pueda verlo, además de mostrar en pantalla que el
#   mensaje es auténtico.
#
#   Si el mensaje ha sido alterado, el programa imprimirá que el mensaje puede no
#   ser auténtico y terminará su ejecución.
#
#   === Referencias ===
#    * https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
#    * https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
#    * https://machinelearningmastery.com/command-line-arguments-for-your-python-script/
#    * https://peps.python.org/pep-0257/
#    * https://pylint.readthedocs.io/en/latest/
#    * http://users.ece.cmu.edu/~adrian/projects/validation/validation.pdf
#