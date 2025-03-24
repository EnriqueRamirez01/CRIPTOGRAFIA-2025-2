"""
Castrillo Ramirez Luis Enrique
Ramirez Martinez Luis Angel
Quiroz Flores Hector Yoram 

Criptografia Grupo 2
Tarea 4: Intercambio de llaves de Diffie-Hellman
"""
# Paso 1: Asignamos los valores públicos
p = 23  # Número primo público acordado entre Alice y Bob
g = 5   # Base pública (raíz primitiva de p)

# Paso 2: Secretos privados (estos no se comparten)
a = 6   # Secreto privado de Alice
b = 15  # Secreto privado de Bob

# Paso 3: Calculamos las llaves públicas usando la fórmula: A = (g)^a mod p y B = (g)^b mod p
A = pow(g, a, p)  # llave pública de Alice
B = pow(g, b, p)  # llave pública de Bob

# Paso 4: calculamos las llaves compartidas usando la formula: s_Alice = (B)^a mod p y s_Bob = (A)^b mod p 
s_Alice = pow(B, a, p)  # Alice calcula la llave compartida
s_Bob = pow(A, b, p)    # Bob calcula la llave compartida

# Mostrar resultados
print("Llave pública de Alice (A):", A) #Resultado Esperado: 8
print("Llave pública de Bob (B):", B) #Resultado Esperado: 19
print("Llave compartida de Alice:", s_Alice) #Resultado Esperado: 2
print("Llave compartida de Bob:", s_Bob) #Resultado Esperado: 2

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