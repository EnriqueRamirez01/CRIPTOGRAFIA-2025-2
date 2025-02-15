"""
Castrillo Ramirez Luis Enrique
Ramirez Martinez Luis Angel
Hector Yoram Quiroz Flores

Criptografia Grupo 2
Tarea 1: Cifrado Cesar
"""
def cifrado_ascii(mensaje, llave):
    mensaje_cifrado = ''
    
    for caracter in mensaje:
        codigo = (ord(caracter) + llave) % 256
        mensaje_cifrado += chr(codigo)
    
    return mensaje_cifrado

def descifrado_ascii(mensaje_cifrado, llave):
    mensaje_descifrado = ''
    
    for caracter in mensaje_cifrado:
        codigo = (ord(caracter) - llave) % 256
        mensaje_descifrado += chr(codigo)
    
    return mensaje_descifrado

# Solicitar al usuario que ingrese el mensaje original
mensaje_original = input("Escribe el mensaje original: ")
llave = int(input("Escribe la llave (número entero): "))

# Cifrar el mensaje
mensaje_cifrado = cifrado_ascii(mensaje_original, llave)
print("Mensaje cifrado:", mensaje_cifrado)

# Descifrar el mensaje
mensaje_descifrado = descifrado_ascii(mensaje_cifrado, llave)
print("Mensaje descifrado:", mensaje_descifrado)