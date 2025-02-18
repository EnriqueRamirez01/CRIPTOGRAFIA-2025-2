"""
Castrillo Ramirez Luis Enrique
Ramirez Martinez Luis Angel
Hector Yoram Quiroz Flores

Criptografia Grupo 2
Tarea 2: Cifrado Vigenere
"""


def generar_clave(mensaje, clave):
    clave = list(clave)
    clave_expandida = ""
    indice = 0
    for caracter in mensaje:
        if caracter.isalpha():
            clave_expandida += clave[indice % len(clave)]
            indice += 1
        else:
            clave_expandida += caracter
    return clave_expandida

def cifrado_vigenere(mensaje, clave):
    clave_expandida = generar_clave(mensaje, clave)
    mensaje_cifrado = ""
    
    for i in range(len(mensaje)):
        if mensaje[i].isalpha():
            base = ord('A') if mensaje[i].isupper() else ord('a')
            codigo = (ord(mensaje[i]) - base + ord(clave_expandida[i]) - ord('a')) % 26 + base
            mensaje_cifrado += chr(codigo)
        else:
            mensaje_cifrado += mensaje[i]
    
    return mensaje_cifrado

def descifrado_vigenere(mensaje_cifrado, clave):
    clave_expandida = generar_clave(mensaje_cifrado, clave)
    mensaje_descifrado = ""
    
    for i in range(len(mensaje_cifrado)):
        if mensaje_cifrado[i].isalpha():
            base = ord('A') if mensaje_cifrado[i].isupper() else ord('a')
            codigo = (ord(mensaje_cifrado[i]) - base - (ord(clave_expandida[i]) - ord('a'))) % 26 + base
            mensaje_descifrado += chr(codigo)
        else:
            mensaje_descifrado += mensaje_cifrado[i]
    
    return mensaje_descifrado

# Solicitar al usuario que ingrese el mensaje original
mensaje_original = input("Escribe el mensaje original: ")
clave = input("Escribe la clave de cifrado: ")

# Cifrar el mensaje
mensaje_cifrado = cifrado_vigenere(mensaje_original, clave)
print("Mensaje cifrado:", mensaje_cifrado)

# Descifrar el mensaje
mensaje_descifrado = descifrado_vigenere(mensaje_cifrado, clave)
print("Mensaje descifrado:", mensaje_descifrado)