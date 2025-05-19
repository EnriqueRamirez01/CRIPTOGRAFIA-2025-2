// Proyecto Final - Criptografia 2025-2
// AES-128 completo: cifrado y de-cifrado según FIPS-197
// Implementado en lenguaje C por pasos


//Integrantes:
//Castrillo Ramirez Luis Enrique
//Ramirez Martinez Luis Angel

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define Nb 4
#define Nk 4
#define Nr 10

typedef uint8_t state_t[4][4];
state_t state;

uint8_t RoundKey[176];
uint8_t Key[16];

uint8_t sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

uint8_t Rcon[11] = {
  0x00, 0x01, 0x02, 0x04, 0x08,
  0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

void load_plaintext(uint8_t *input) {
    int i;
    for (i = 0; i < 16; ++i)
        state[i % 4][i / 4] = input[i];
}

void load_key(uint8_t *input) {
    memcpy(Key, input, 16);
}

void print_state(state_t st, const char *label) {
    int i, j;
    printf("\n%s:\n", label);
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            printf("%02X ", st[i][j]);
        }
        printf("\n");
    }
}

// ---------------------------- ADD ROUND KEY ----------------------------
// Aplica la clave de ronda al estado (XOR por columnas)
void AddRoundKey(int round) {
    int col, row;
    for (col = 0; col < Nb; col++) {
        for (row = 0; row < 4; row++) {
            state[row][col] ^= RoundKey[round * Nb * 4 + col * 4 + row];
        }
    }
}

// Imprime la clave de una ronda específica
void print_round_key(int round) {
    int row, col;
    printf("\n=====Round %d Key:=====\n", round);
    for (row = 0; row < 4; row++) {
        for (col = 0; col < Nb; col++) {
            printf("%02X ", RoundKey[round * Nb * 4 + col * 4 + row]);
        }
        printf("\n");
    }
}

void SubBytes() {
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < Nb; j++)
            state[i][j] = sbox[state[i][j]];
}

void ShiftRows() {
    uint8_t temp;

    // Fila 1 (desplazar 1 byte a la izquierda)
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Fila 2 (desplazar 2 bytes)
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Fila 3 (desplazar 3 bytes a la izquierda ? equivale a 1 byte a la derecha)
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x >> 7) * 0x1b);  // Multiplicación por x (0x02) en GF(2^8)
}

void MixColumns() {
    uint8_t i;
    uint8_t Tmp, Tm, t;

    for (i = 0; i < Nb; ++i) {
        t = state[0][i];
        Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];

        Tm = state[0][i] ^ state[1][i];
        Tm = xtime(Tm);
        state[0][i] ^= Tm ^ Tmp;

        Tm = state[1][i] ^ state[2][i];
        Tm = xtime(Tm);
        state[1][i] ^= Tm ^ Tmp;

        Tm = state[2][i] ^ state[3][i];
        Tm = xtime(Tm);
        state[2][i] ^= Tm ^ Tmp;

        Tm = state[3][i] ^ t;
        Tm = xtime(Tm);
        state[3][i] ^= Tm ^ Tmp;
    }
}

void RotWord(uint8_t *word) {
    uint8_t temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

void SubWord(uint8_t *word) {
    int i;
    for (i = 0; i < 4; i++)
        word[i] = sbox[word[i]];
}

void KeyExpansion() {
    uint32_t i;
    uint8_t temp[4];
    for (i = 0; i < Nk * 4; i++)
        RoundKey[i] = Key[i];

    for (i = Nk; i < Nb * (Nr + 1); i++) {
        temp[0] = RoundKey[4 * (i - 1)];
        temp[1] = RoundKey[4 * (i - 1) + 1];
        temp[2] = RoundKey[4 * (i - 1) + 2];
        temp[3] = RoundKey[4 * (i - 1) + 3];

        if (i % Nk == 0) {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[i / Nk];
        }

        RoundKey[4 * i] = RoundKey[4 * (i - Nk)] ^ temp[0];
        RoundKey[4 * i + 1] = RoundKey[4 * (i - Nk) + 1] ^ temp[1];
        RoundKey[4 * i + 2] = RoundKey[4 * (i - Nk) + 2] ^ temp[2];
        RoundKey[4 * i + 3] = RoundKey[4 * (i - Nk) + 3] ^ temp[3];
    }
}

void Cipher() {
    int round = 0;

    // Paso inicial: AddRoundKey(0)
    print_state(state, "Estado inicial");
    print_round_key(round);
    AddRoundKey(round);
    print_state(state, "Después de AddRoundKey 0");

    // Rondas 1 a 9
    for (round = 1; round < Nr; ++round) {
        SubBytes();
        print_state(state, "Después de SubBytes");

        ShiftRows();
        print_state(state, "Después de ShiftRows");

        MixColumns();
        print_state(state, "Después de MixColumns");

        print_round_key(round);
        AddRoundKey(round);
        print_state(state, "Después de AddRoundKey");
    }

    // Última ronda (sin MixColumns)
    SubBytes();
    print_state(state, "Después de SubBytes (última ronda)");

    ShiftRows();
    print_state(state, "Después de ShiftRows (última ronda)");

    print_round_key(round);
    AddRoundKey(round);
    print_state(state, "Después de AddRoundKey (última ronda)");
}

uint8_t inv_sbox[256] = {
  0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
  0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
  0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
  0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
  0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
  0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
  0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
  0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
  0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
  0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
  0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
  0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
  0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
  0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
  0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
  0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

void InvSubBytes() {
	int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < Nb; j++)
            state[i][j] = inv_sbox[state[i][j]];
}

void InvShiftRows() {
    uint8_t temp;

    // Fila 1 (rotar 1 a la derecha)
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // Fila 2 (rotar 2)
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Fila 3 (rotar 3 a la derecha ? equivale a 1 a la izquierda)
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

uint8_t Multiply(uint8_t x, uint8_t y) {
    uint8_t result = 0;
    while (y) {
        if (y & 1) result ^= x;
        x = xtime(x);
        y >>= 1;
    }
    return result;
}

void InvMixColumns() {
    uint8_t i;
    uint8_t a, b, c, d;

    for (i = 0; i < Nb; i++) {
        a = state[0][i];
        b = state[1][i];
        c = state[2][i];
        d = state[3][i];

        state[0][i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        state[1][i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        state[2][i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        state[3][i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}

void InvCipher() {
    int round = Nr;

    print_round_key(round);
    AddRoundKey(round);
    print_state(state, "Después de AddRoundKey (ronda final)");

    for (round = Nr - 1; round >= 1; --round) {
        InvShiftRows();
        print_state(state, "Después de InvShiftRows");

        InvSubBytes();
        print_state(state, "Después de InvSubBytes");

        print_round_key(round);
        AddRoundKey(round);
        print_state(state, "Después de AddRoundKey");

        InvMixColumns();
        print_state(state, "Despues de InvMixColumns");
    }

    InvShiftRows();
    InvSubBytes();
    print_round_key(0);
    AddRoundKey(0);
    print_state(state, "Estado recuperado (plaintext)");
}


int main() {
    int opcion;
    do {
        printf("\n=== MENU AES-128 ===\n");
        printf("1. Cifrar texto\n");
        printf("2. Descifrar texto (hexadecimal)\n");
        printf("3. Salir\n");
        printf("Selecciona una opción: ");
        scanf("%d", &opcion);
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF);  // limpia buffer completo

        if (opcion == 1) {
            char texto[17], clave[17];
            printf("Ingrese el texto plano (16 caracteres): ");
            fgets(texto, sizeof(texto), stdin);
            if (texto[strlen(texto) - 1] == '\n') 
                texto[strlen(texto) - 1] = '\0';
            
            else {
                int ch;
                while ((ch = getchar()) != '\n' && ch != EOF);
            }

            if (strlen(texto) != 16) {
                printf("El texto debe tener exactamente 16 caracteres.\n");
                continue;
            }

            printf("Ingrese la clave AES (16 caracteres): ");
            fgets(clave, sizeof(clave), stdin);
            if (clave[strlen(clave) - 1] == '\n') 
                clave[strlen(clave) - 1] = '\0';
            
            else {
                int ch;
                while ((ch = getchar()) != '\n' && ch != EOF);
            }
        
            if (strlen(clave) != 16) {
                printf("La clave debe tener exactamente 16 caracteres.\n");
                continue;
            }

            load_key((uint8_t *)clave);
            load_plaintext((uint8_t *)texto);

            printf("\n==== C I F R A D O ====\n");
            KeyExpansion();
            Cipher();

            printf("\nTexto cifrado (hexadecimal):\n");
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < Nb; j++)
                    printf("%02X ", state[j][i]);
            printf("\n");

        } 
        
        else if (opcion == 2) {
            char hex[33], clave[17];
            uint8_t ciphertext[16];

            printf("Ingrese el texto cifrado (32 caracteres hex): ");
            fgets(hex, sizeof(hex), stdin);
            if (hex[strlen(hex) - 1] == '\n') 
                hex[strlen(hex) - 1] = '\0';
            
            else {
                int ch;
                while ((ch = getchar()) != '\n' && ch != EOF); // <--- limpia el salto que quedó
            }
            
            if (strlen(hex) != 32) {
                printf("El texto cifrado debe tener exactamente 32 caracteres hexadecimales.\n");
                continue;
            }

            for (int i = 0; i < 16; i++) {
                sscanf(&hex[i * 2], "%2hhx", &ciphertext[i]);
                state[i % 4][i / 4] = ciphertext[i];
            }
            
            printf("Ingrese la clave AES (16 caracteres): ");
            if (fgets(clave, sizeof(clave), stdin) == NULL || strlen(clave) < 1) {
                printf("Error al leer la clave.\n");
                continue;
            }
            
            if (clave[strlen(clave) - 1] == '\n') 
                clave[strlen(clave) - 1] = '\0';
            
            else {
                int ch;
                while ((ch = getchar()) != '\n' && ch != EOF);
            
            }
            
            size_t len = strlen(clave);
            if (len != 16) {
                printf("La clave debe tener exactamente 16 caracteres (recibidos: %zu).\n", len);
                continue;
            }
            
            if (strlen(clave) != 16) {
                printf("La clave debe tener exactamente 16 caracteres.\n");
                continue;
            }

            load_key((uint8_t *)clave);
            KeyExpansion();

            printf("\n==== D E S C I F R A D O ====\n");
            InvCipher();

            printf("\nTexto plano recuperado: ");
            char recovered[17];
            for (int i = 0; i < 16; i++)
                recovered[i] = state[i % 4][i / 4];
            recovered[16] = '\0';
            printf("%s\n", recovered);

        } 
        
        else if (opcion == 3) {
            printf("Muchas Gracias. Vuelva pronto. Saliendo del programa...\n");
        } 
        
        else {
            printf("Opción inválida. Intenta de nuevo.\n");
        }

    } while (opcion != 3);

    return 0;
}