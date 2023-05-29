Criptografía-RSA
===

Este es un proyecto para el electivo de Criptografía Aplicada, el cual que consiste en tres programas escritos en Python
con el objetivo de implementar la [encriptación RSA](https://es.wikipedia.org/wiki/RSA) en un contexto práctico.

La implementación lograda es más bien minimal, y sirve para ilustrar perfectamente el proceso de encriptación de
mensajes en texto plano utilizando las llaves RSA de dos usuarios.

Programas
---

El proyecto cuenta con tres scripts de Python:

  1. keygen.py: Genera pares de llaves RSA.
  2. cipher.py: Cifra texto plano utilizando una llave RSA privada del emisor y la llave pública del receptor.
  3. decipher.py: Descifra texto cifrado utilizando la llave privada del receptor y la llave pública del emisor.

### keygen.py

    Generar par de llaves RSA

### cipher.py

    Cifrar mensajes (RSA)

    argumentos posicionales:
      --private-key                   Llave RSA privada
      --public-key                    Llave RSA publica

### decipher.py

    Descifrar mensajes (RSA)

    argumentos posicionales:
      --public-key                    Llave RSA publica
      --private-key                   Llave RSA privada

Autores
---

  - José Benavente
  - Daniel Aguayo
