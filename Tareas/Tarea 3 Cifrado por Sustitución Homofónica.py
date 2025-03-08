"""
Castrillo Ramirez Luis Enrique
Ramirez Martinez Luis Angel
Quiroz Flores Hector Yoram 

Criptografia Grupo 2
Tarea 3: Cifrado por Sustitución Homofónica
"""

import random

# Definimos el alfabeto y sus claves binarias predefinidas asegurando mínimo 3 y máximo 10 claves por letra
CLAVES = {
    "A": ["0000000", "0000001", "0000010", "0000011", "0000100"],
    "B": ["0000101", "0000110", "0000111"],
    "C": ["0001000", "0001001", "0001010", "0001011"],
    "D": ["0001100", "0001101", "0001110"],
    "E": ["0001111", "0010000", "0010001", "0010010", "0010011", "0010100", "0010101"],
    "F": ["0010110", "0010111", "0011000"],
    "G": ["0011001", "0011010", "0011011"],
    "H": ["0011100", "0011101", "0011110"],
    "I": ["0011111", "0100000", "0100001", "0100010"],
    "J": ["0100011", "0100100", "0100101"],
    "K": ["0100110", "0100111", "0101000"],
    "L": ["0101001", "0101010", "0101011"],
    "M": ["0101100", "0101101", "0101110", "0101111"],
    "N": ["0110000", "0110001", "0110010", "0110011"],
    "Ñ": ["0110101", "0110110", "1001101"],
    "O": ["0110111", "0111000", "0111001", "0111010", "0111011"],
    "P": ["0111100", "0111101", "0111110"],
    "Q": ["0111111", "1101001", "1111000"],
    "R": ["1110011", "1101100", "1110101"],
    "S": ["1001010", "1100011", "1011100"],
    "T": ["1110111", "1010011", "0110100"],
    "U": ["1110100", "1100101", "1100111"],
    "V": ["1100010", "1010101", "1010000"],
    "W": ["1101101", "1001000", "1001001"],
    "X": ["1110010", "1111011", "1000010"],
    "Y": ["1000101", "1111010", "1101011"],
    "Z": ["1010001", "1011001", "1100000"]
}

# Verificamos que no haya claves repetidas en diferentes letras
def verificar_unicidad():
    claves_usadas = set()
    for letra, binarios in CLAVES.items():
        for binario in binarios:
            if binario in claves_usadas:
                raise ValueError(f"Clave duplicada detectada: {binario} en la letra {letra}")
            claves_usadas.add(binario)

# Creamos el diccionario inverso para descifrar
CLAVES_INVERSAS = {binario: letra for letra, binarios in CLAVES.items() for binario in binarios}

# Función para cifrar
def cifrar(texto):
    texto = texto.upper()
    cifrado = []
    for letra in texto:
        if letra in CLAVES:
            cifrado.append(random.choice(CLAVES[letra]))
        else:
            cifrado.append(letra)  # Mantener espacios u otros caracteres sin cifrar
    return " ".join(cifrado)

# Función para descifrar
def descifrar(cifrado):
    binarios = cifrado.split()
    texto = "".join(CLAVES_INVERSAS.get(b, "?") for b in binarios)  # '?' para claves desconocidas
    return texto

# Función para mostrar el menú
def menu():
    while True:
        print("\nMenú:")
        print("1. Cifrar un mensaje")
        print("2. Descifrar un mensaje")
        print("3. Salir")
        opcion = input("Elige una opción: ")

        if opcion == "1":
            mensaje = input("Ingresa el mensaje a cifrar: ")
            cifrado = cifrar(mensaje)
            print("Mensaje cifrado:", cifrado)
        elif opcion == "2":
            cifrado = input("Ingresa el mensaje cifrado: ")
            descifrado = descifrar(cifrado)
            print("Mensaje descifrado:", descifrado)
        elif opcion == "3":
            print("Saliendo del programa.")
            break
        else:
            print("Opción no válida. Inténtalo de nuevo.")

# Verificación de claves antes de ejecutar el programa
try:
    verificar_unicidad()
    menu()
except ValueError as e:
    print("Error en las claves:", e)