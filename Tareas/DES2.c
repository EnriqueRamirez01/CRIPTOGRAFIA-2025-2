/*
Castrillo Ramirez Luis Enrique
Ramirez Martinez Luis Angel
Quiroz Flores Hector Yoram

Criptografia Grupo 2
Tarea 5: Cifrado simétrica "DES"
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//Para transformar la llave

void ejecutaPC1(_Bool*, unsigned char*, _Bool*);
void particionDerIzq(_Bool * vector, unsigned char length, _Bool *llaveDer,_Bool *llaveIzq);
void printVector(_Bool* ip, unsigned char length);
void rotacion(_Bool *llaveDer,_Bool *llaveIzq, unsigned char[]);
void EjecutaCorrimiento(_Bool *,unsigned char, _Bool*);
void unirDerIzq(_Bool *vector,unsigned char length, _Bool *llaveDer, _Bool *llaveIzq);
void ejecutaPC2(_Bool * key, unsigned char *PC2, _Bool *nuevaLlave);
void ejecutarIP(_Bool * message, unsigned char * IP_, _Bool * mensajeD, _Bool * mensajeI);
void ejecutarPermutacionP(_Bool * SmR, unsigned char * P, _Bool *PmR);
void funcionF(_Bool *mR, _Bool *key, unsigned char *EBitSeleccion, unsigned char S[][4][16], unsigned char *P, _Bool * SalidaF);
void funcionE(_Bool *ivector, unsigned char* EBitSeleccion, _Bool* oVector);
void funcionS(_Bool * iVector, unsigned char S[][4][16], _Bool * oVector);
void XOR(_Bool*, _Bool*, unsigned char, _Bool*);
void char2_Bool(unsigned char charVar, _Bool* boolVec, unsigned char nBits);
void EjecutaIPInv(_Bool* PreCrypto, unsigned char* IPInv, _Bool* Crypto);

void printVector(_Bool* ip, unsigned char length){
    int i;
    for (i = 0; i < length; i++)
        printf("%d", *(ip + i));
    printf("\n");
}
void ejecutaPC1(_Bool * key, unsigned char * PC1, _Bool *nuevaLlave)
{
    unsigned char i;
    for(i=0; i<56; i++)
    {
        nuevaLlave[i]=key[PC1[i]-1];
    }
}

void particionDerIzq(_Bool * vector, unsigned char length, _Bool *llaveDer, _Bool *llaveIzq)
{
    for(int i=0; i<(length/2); i++)
    {
        llaveIzq[i] =vector[i];
        llaveDer[i] =vector[i + (length/2)];
    }
}




void EjecutaCorrimiento(_Bool *iVector,unsigned char nShifts, _Bool *oVector)
{
    unsigned char shiftCntr,bitCntr,nBits=28;
    _Bool iVectorTmp[28];
    for(bitCntr=0; bitCntr<nBits; bitCntr++)
    {
        iVectorTmp[bitCntr]=iVector[bitCntr];
    }
    for(shiftCntr=0; shiftCntr<nShifts; shiftCntr++)
    {
        oVector[nBits-1]=iVectorTmp[0];
        for(bitCntr=1; bitCntr<nBits; bitCntr++)
        {
            oVector[bitCntr-1]=iVectorTmp[bitCntr];
        }
        for(bitCntr=0; bitCntr<nBits; bitCntr++)
        {
            iVectorTmp[bitCntr]=oVector[bitCntr];
        }
    }

}

void unirDerIzq(_Bool *vector, unsigned char length, _Bool *llaveDer, _Bool * llaveIzq)
{
    int i;
    for(i=0; i<(length/2); i++)
    {
        vector[i]=llaveIzq[i];
        vector[i +(length/2)]=llaveDer[i];
    }
}


void ejecutarIP(_Bool *mensaje, unsigned char * IP_, _Bool * mensajeD, _Bool *mensajeI)
{
    _Bool nuevoMensaje[64];
    unsigned char i;
    for(i=0; i<64; i++)
    {
        nuevoMensaje[i]=mensaje[IP_[i]-1];

    }
    particionDerIzq(nuevoMensaje,64,mensajeD,mensajeI);
}

void ejecutarPermutacionP(_Bool * SmR, unsigned char * P, _Bool *PmR)
{
    unsigned char i;
    for(i=0; i<32; i++)
    {
        PmR[i]=SmR[P[i]-1];
    }
}

void ejecutaPC2(_Bool *key, unsigned char *PC2,_Bool * nuevaLlave)
{
    unsigned char i;
    for(i=0; i<48; i++)
    {
        nuevaLlave[i]=key[PC2[i]-1];
    }
}

void XOR(_Bool * vector1, _Bool* vector2, unsigned char nElementos, _Bool *vectorRes){
    int i;
    for(i=0;i<nElementos;i++){
        if (((vector1[i] == 1) && (vector2[i] == 0)) || ((vector1[i] == 0) && (vector2[i] == 1))){
            vectorRes[i]=1;
        }
        else if(((vector1[i] == 1) && (vector2[i] == 1)) || ((vector1[i] == 0) && (vector2[i] == 0))){
            vectorRes[i]=0;
        }
    }
}

void funcionF(_Bool *mR, _Bool* key, unsigned char* EBitSeleccion, unsigned char S[][4][16], unsigned char *P, _Bool * SalidaF)
{
    _Bool EmR[48] = {0}, KEmR[48] = {0}, SmR[32] = {0}, PmR[32] = {0};
    funcionE(mR, EBitSeleccion, EmR);
    XOR(key, EmR, 48, KEmR);
    funcionS(KEmR, S, SmR);
    ejecutarPermutacionP(SmR,P,PmR);
    memcpy(SalidaF, PmR, 32 * sizeof(PmR[0]));
}

void funcionE(_Bool *iVector, unsigned char* EBitSeleccion, _Bool* oVector)
{
    unsigned char i;
    for(i=0; i<48; i++)
    {
        oVector[i]=iVector[EBitSeleccion[i]-1];
    }
}

void char2_Bool(unsigned char charVar, _Bool * boolVec, unsigned char nBits){
    int i;
    for(i=0;i<nBits;i++){
        if(charVar%2==0){
            boolVec[nBits-i-1]=0;

        }else{
            boolVec[nBits-i-1]=1;
        }
        charVar=(charVar-(charVar%2))/2;
    }
}

void funcionS(_Bool * iVector, unsigned char S[][4][16], _Bool * oVector)
{
    int i,j;
    unsigned char charTmp,row,col;
    _Bool boolTmp[4]= {0};
    for(i=0; i<8; i++)
    {
        row=iVector[i*6]*2+iVector[i*6+5]*1;
        col=iVector[i*6+1]*8+iVector[i*6+2]*4+iVector[i*6+3]*2+iVector[i*6+4]*1;
        charTmp= S[i][row][col];
        char2_Bool(charTmp,boolTmp,4);
        for(j=0; j<4; j++)
        {
            oVector[i*4+j]=boolTmp[j];
        }
    }
}

void EjecutaIPInv(_Bool* PreCrypto, unsigned char* IPInv, _Bool* Crypto){
    unsigned char i;
    for(i=0;i<64;i++){
        Crypto[i]=PreCrypto[IPInv[i]-1];
    }
}

int main()
{
    //Para la transformacion de la llave

    unsigned char PC1[] =
    {
        57, 49, 41, 33, 25, 17,  9,
        1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4
    };

    _Bool  message[64]= {0, 0, 0, 0, 0, 0, 0, 1,
                         0, 0, 1, 0, 0, 0, 1, 1,
                         0, 1, 0, 0, 0, 1, 0, 1,
                         0, 1, 1, 0, 0, 1, 1, 1,
                         1, 0, 0, 0, 1, 0, 0, 1,
                         1, 0, 1, 0, 1, 0, 1, 1,
                         1, 1, 0, 0, 1, 1, 0, 1,
                         1, 1, 1, 0, 1, 1, 1, 1
                        };

    _Bool key[64]= {0, 0, 0, 1, 0, 0, 1, 1,
                    0, 0, 1, 1, 0, 1, 0, 0,
                    0, 1, 0, 1, 0, 1, 1, 1,
                    0, 1, 1, 1, 1, 0, 0, 1,
                    1, 0, 0, 1, 1, 0, 1, 1,
                    1, 0, 1, 1, 1, 1, 0, 0,
                    1, 1, 0, 1, 1, 1, 1, 1,
                    1, 1, 1, 1, 0, 0, 0, 1
                   };
    unsigned char Tablarotacion[16]= {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

    unsigned char PC2[48]= {14, 17, 11, 24, 1, 5, 3, 28,
                            15, 6, 21, 10, 23, 19, 12, 4,
                            26, 8, 16, 7, 27, 20, 13, 2,
                            41, 52, 31, 37, 47, 55, 30,40,
                            51, 45, 33, 48, 44, 49, 39, 56,
                            34, 53, 46, 42, 50, 36, 29, 32
                           };

    //Para hacer la permutacion en el mensaje
    unsigned char IP_[64]= {58, 50, 42, 34, 26, 18, 10, 2,
                            60, 52, 44, 36, 28, 20, 12, 4,
                            62, 54, 46, 38, 30, 22, 14, 6,
                            64, 56, 48, 40, 32, 24, 16, 8,
                            57, 49, 41, 33, 25, 17, 9, 1,
                            59, 51, 43, 35, 27, 19, 11, 3,
                            61, 53, 45, 37, 29, 21, 13, 5,
                            63, 55, 47, 39, 31, 23, 15, 7
                           };
    _Bool mensajeI[17][32];
    _Bool mensajeD[17][32];
    _Bool SalidaF[32]={0};
    unsigned char EBitSeleccion[48]= {32, 1, 2, 3, 4, 5, 4, 5,
                                      6, 7, 8, 9, 8, 9, 10, 11,
                                      12, 13, 12, 13, 14, 15, 16,
                                      17, 16, 17, 18, 19, 20, 21,
                                      20, 21, 22, 23, 24, 25, 24,
                                      25, 26, 27, 28, 29, 28, 29,
                                      30, 31, 32, 1
                                     };
    unsigned char S[8][4][16] =
    {
        {   {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}, {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0}, {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        },
        {   {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        },
        {   {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        },
        {   {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        },
        {   {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
        },
        {   {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        },
        {   {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        },
        {   {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        }
    };

    unsigned char P[32]={16, 7, 20, 21, 29, 12, 28, 17,
                         1, 15, 23, 26, 5, 18, 31, 10, 2,
                         8, 24, 14, 32, 27, 3, 9, 19, 13,
                         30, 6, 22, 11, 4, 25};
    unsigned char IPInv[64] = {40, 8, 48, 16, 56, 24, 64, 32,
                               39, 7, 47, 15, 55, 23, 63, 31,
                               38, 6, 46, 14, 54, 22, 62, 30,
                               37, 5, 45, 13, 53, 21, 61, 29,
                               36, 4, 44, 12, 52, 20, 60, 28,
                               35, 3, 43, 11, 51, 19, 59, 27,
                               34, 2, 42, 10, 50, 18, 58, 26,
                               33, 1, 41, 9, 49, 17, 57, 25};

    _Bool nuevaLlave[58];
    //17 llaves de longitud de 56/2
    _Bool llaveIzq[17][28];
    _Bool llaveDer[17][28];
    _Bool llaveAntesPC2[16][56];
    _Bool llaveDespuesPC2[16][48];
    //Se ejecuta la permutacion PC1
    ejecutaPC1(key,PC1,nuevaLlave);
    //Ya que se tiene PC1 se divide la llave en dos mitades
    particionDerIzq(nuevaLlave,56,llaveDer[0],llaveIzq[0]);
    //Ya con las dos mitades, se hace una rotación para obtener 16 llaves
    unsigned char i;
    for(i=1; i<=16; i++)
    {
        EjecutaCorrimiento(llaveDer[i-1],Tablarotacion[i-1],llaveDer[i]);
        EjecutaCorrimiento(llaveIzq[i-1],Tablarotacion[i-1],llaveIzq[i]);
        unirDerIzq(llaveAntesPC2[i-1],56,llaveDer[i],llaveIzq[i] );
    }

    //Ya se tienen las 16 llaves en la estructura de datos, ahora se aplica PC2:
    for(i=0; i<16; i++)
    {
        ejecutaPC2(llaveAntesPC2[i],PC2,llaveDespuesPC2[i]);
    }
    //Ahora se usa el mensaje para realizar la permutacion IP
    ejecutarIP(message,IP_,mensajeD[0],mensajeI[0]);

    //Se inicia el bucle de modificacion del mensaje
    for(i=1; i<=16; i++)
    {
        memcpy(mensajeI[i], mensajeD[i-1],32*sizeof(mensajeD[i][0]));
        funcionF(mensajeD[i-1],llaveDespuesPC2[i-1],EBitSeleccion,S,P,SalidaF);
        XOR(mensajeI[i-1],SalidaF,32,mensajeD[i]);
    }

    _Bool RL[64];
    _Bool Crypto[64];
    for(int i=0;i<32;i++){
        RL[i]=mensajeD[16][i];
        RL[i+32]=mensajeI[16][i];
    }
    EjecutaIPInv(RL, IPInv, Crypto);
    printf("Mensaje cifrado final:\n");
for (int i = 0; i < 64; i++) {
    printf("%d", Crypto[i]);
    if ((i + 1) % 8 == 0) printf(" "); // Opcional, agrupa en bytes
}
printf("\n");

}
