"""
Castrillo Ramirez Luis Enrique
Ramirez Martinez Luis Angel
Quiroz Flores Hector Yoram 

Criptografia Grupo 2
Tarea 4: Intercambio de llaves de Diffie-Hellmana
"""
# Paso 1: Selección de los valores públicos
print("Protocolo de Intercambio de Claves de Diffie-Hellman\n")

# Ingreso del número primo
def es_primo(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

# Verificación e ingreso del número primo
while True:
    p = int(input("Ingresa un número primo (p): "))
    if es_primo(p):
        break
    else:
        print("Ese número no es primo. Intenta con otro (por ejemplo: 17, 23, 29)")

# Función para verificar si una raíz es primitiva
def es_raiz_primitiva(g, p):
    residuos = set()
    for i in range(1, p):
        residuos.add(pow(g, i, p))
    return len(residuos) == p - 1

# Buscar una raíz primitiva válida automáticamente
for g in range(2, p):
    if es_raiz_primitiva(g, p):
        break

print(f"Raíz primitiva seleccionada automáticamente: g = {g}")

# Paso 2: Selección de secretos privados
print("\n--- Secretos Privados ---")
a = int(input("Alice, elige tu número secreto (a): "))
b = int(input("Bob, elige tu número secreto (b): "))

# Paso 3: Cálculo de llaves públicas
A = pow(g, a, p)  # Llave pública de Alice
B = pow(g, b, p)  # Llave pública de Bob

print(f"\nLlave pública de Alice (A): {A}")
print(f"Llave pública de Bob (B): {B}")

# Paso 4: Cálculo de la llave compartida
clave_alice = pow(B, a, p)
clave_bob = pow(A, b, p)

print("\n--- Clave de sesión compartida ---")
print(f"Alice calcula la clave: {clave_alice}")
print(f"Bob calcula la clave: {clave_bob}")

# Verificación
if clave_alice == clave_bob:
    print(f"\nIntercambio exitoso: clave de sesión compartida = {clave_alice}")
else:
    print("\nError: las claves no coinciden")


"""
CALCULOS QUE SE REALIZARON EN LOS PASOS 3 Y 4
PASO 3: CALCULO DE LLAVES PUBLICAS
Cálculo de A:
A = (g)^a mod p
A = (5)^6 mod 23 
A = 15625 mod 23 
A = 8

Cálculo de B:
B = (g)^b mod p
B = (5)^15 mod 23 
B = 30 517 578 125 mod 23 
B = 19

PASO 4: CALCULO DE LLAVES COMPARTIDA
Cálculo de LLAVE compartida por Alice:
s_Alice = (B)^a mod p  
s_Alice = (19)^6 mod 23
s_Alice = 47 045 881 mod 23
s_Alice = 2

Cálculo de LLAVE compartida por Bob:
s_Bob = (A)^b mod p 
s_Bob = (8)^15 mod 23
s_Bob = 35 184 372 088 832 mod 23
s_Bob = 2
"""