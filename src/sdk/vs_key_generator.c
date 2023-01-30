#include "vs_key_generator.h"

static unsigned int randseed = 0;
static unsigned int matrixseed = 0;

//8bit internal xor table
int xor[] = {0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
			 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
			 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
			 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
			 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
			 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
			 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
			 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
			 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
			 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
			 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
			 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
			 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
			 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
			 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
			 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0};

//8bit Hamming weight table
int HW[] =  {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
			 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
			 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
			 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
			 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
			 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
			 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
			 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
			 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
			 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
			 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
			 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
			 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
			 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
			 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
			 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8};

uint8_t idM4[4] = {0x08, 0x04, 0x02, 0x01};
uint8_t idM8[8] = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};
uint16_t idM16[16] = {0x8000, 0x4000, 0x2000, 0x1000, 0x8001, 0x400e, 0x200c, 0x1003,
                      0x8010, 0x4020, 0x2030, 0x1040, 0x81fe, 0x412f, 0x234f, 0x12e3};
uint32_t idM32[32] = {0x80000000, 0x40000000, 0x20000000, 0x10000000,
                      0x80000003, 0x4000000f, 0x20000002, 0x10000001,
                      0x80000034, 0x40000012, 0x2000003f, 0x1000003e,
                      0x8000012c, 0x4000013f, 0x2000098c, 0x10000970,
                      0x80000912, 0x4000321c, 0x2000125f, 0x1000133e,
                      0x800235ef, 0x400323ff, 0x2002123e, 0x100e342f,
                      0x8097843f, 0x40321456, 0x20321098, 0x101123fe,
                      0x8090213f, 0x421346fe, 0x2111233f, 0x10002132};
uint64_t idM64[64] = {0x8000000000000000, 0x4000000000000000, 0x2000000000000000, 0x1000000000000000,
                      0x800000000000000f, 0x400000000000000f, 0x2000000000000003, 0x100000000000000e,
                      0x80000000000000a2, 0x4000000000000032, 0x2000000000000010, 0x1000000000000019,
                      0x80000000000000a1, 0x4000000000000098, 0x2000000000000012, 0x1000000000000fe3,
                      0x800000000000,     0x400000000000,     0x200000000000,     0x100000000000,
					  0x80000000000,      0x40000000000,      0x20000000000,      0x10000000000,
					  0x8000000000,		  0x4000000000, 	  0x2000000000, 	  0x1000000000,
					  0x800000000,		  0x400000000, 		  0x200000000, 		  0x100000000,
					  0x80000000,		  0x40000000,		  0x20000000, 		  0x10000000,
					  0x8000000,		  0x4000000, 		  0x2000000, 		  0x1000000, 
					  0x800000,			  0x400000, 		  0x200000, 		  0x100000,
					  0x80000,			  0x40000,			  0x20000,			  0x10000,
					  0x8000,			  0x4000,			  0x2000, 			  0x1000,
					  0x800,		      0x400,		      0x200, 			  0x100,
					  0x80,				  0x40, 			  0x20, 			  0x10,
                      0x8, 				  0x4, 				  0x2, 				  0x1};

static u32 TypeII[10][16][256];//Type II
static u32 TypeIII[9][16][256];//Type III
static u8 TypeIV_II[9][4][3][8][16][16];
static u8 TypeIV_III[9][4][3][8][16][16];
static u8 TypeIa[16][256];
static u8 TypeIb[16][256];

static const u8 SBox[256] = {
		    0x33, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		    0xea, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		    0xf7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		    0x14, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		    0x99, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		    0x73, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		    0x10, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		    0xf1, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		    0x0d, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		    0x50, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		    0x31, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		    0x45, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		    0x23, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		    0x12, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		    0x13, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		    0x16, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

void SetRandSeed(unsigned int seed1, unsigned int seed2)
{
    randseed = seed1;
	matrixseed = seed2;
}

void initM4(M4 *Mat)//initial Matrix 4*4
{
    int i;
    for(i = 0; i < 4; i++)
    {
        (*Mat).M[i] = 0;
    }
}
void initM8(M8 *Mat)//initial Matrix 8*8
{
    int i;
    for(i = 0; i < 8; i++)
    {
        (*Mat).M[i] = 0;
    }
}
void initM16(M16 *Mat)//initial Matrix 16*16
{
    int i;
    for(i = 0; i < 16; i++)
    {
        (*Mat).M[i] = 0;
    }
}
void initM32(M32 *Mat)//initial Matrix 32*32
{
    int i;
    for(i = 0; i < 32; i++)
    {
        (*Mat).M[i] = 0;
    }
}
void initM64(M64 *Mat)//initial Matrix 64*64
{
    int i;
    for(i = 0; i < 64; i++)
    {
        (*Mat).M[i] = 0;
    }
}
void initM128(M128 *Mat)//initial Matrix 128*128
{
    int i;
    for(i = 0; i < 128; i++)
    {
        (*Mat).M[i][0] = 0;
        (*Mat).M[i][1] = 0;
    }
}
void initV4(V4 *Vec)//initial Vector 4*1
{
    (*Vec).V = 0;
}
void initV8(V8 *Vec)//initial Vector 8*1
{
    (*Vec).V = 0;
}
void initV16(V16 *Vec)//initial Vector 16*1
{
    (*Vec).V = 0;
}
void initV32(V32 *Vec)//initial Vector 32*1
{
    (*Vec).V = 0;
}
void initV64(V64 *Vec)//initial Vector 64*1
{
    (*Vec).V = 0;
}
void initV128(V128 *Vec)//initial Vector 128*1
{
    (*Vec).V[0] = 0;
    (*Vec).V[1] = 0;
}
void randM4(M4 *Mat)//randomize Matrix 4*4 
{
    int i;
    InitRandom((randseed) ^ matrixseed);
    for(i = 0; i < 4; i++)
    {
        (*Mat).M[i] = cus_random() & 0x0f;
    }
}
void randM8(M8 *Mat)//randomize Matrix 8*8 
{
    int i;
    InitRandom((randseed) ^ matrixseed);
    for(i = 0; i < 8; i++)
    {
        (*Mat).M[i] = cus_random();
    }
}
void randM16(M16 *Mat)//randomize Matrix 16*16 
{
    int i;
    InitRandom((randseed) ^ matrixseed);
    for(i = 0; i < 16; i++)
    {
        (*Mat).M[i] = cus_random();
    }
}
void randM32(M32 *Mat)//randomize Matrix 32*32 
{
    int i;
    InitRandom((randseed) ^ matrixseed);
    for(i = 0; i < 32; i++)
    {
        (*Mat).M[i] = cus_random();
    }
}
void randM64(M64 *Mat)//randomize Matrix 64*64 
{
    int i;
    uint32_t *m;
    InitRandom((randseed) ^ matrixseed);
    for(i = 0; i < 64; i++)
    {
        m = (uint32_t*)&((*Mat).M[i]);
        *(m+1) = cus_random();
        *m = cus_random();
    }
}
void randM128(M128 *Mat)//randomize Matrix 128*128 
{
    int i;
    uint32_t *m;
    InitRandom((randseed) ^ matrixseed);
    for(i = 0; i < 128; i++)
    {
        m = (uint32_t*)&((*Mat).M[i][0]);
        *(m+1) = cus_random();
        *m = cus_random();
        m = (uint32_t*)&((*Mat).M[i][1]);
        *(m+1) = cus_random();
        *m = cus_random();
    }
}
void identityM4(M4 *Mat)//identity matrix 4*4
{
    int i;
    for(i = 0; i < 4; i++)
    {
        (*Mat).M[i] = idM4[i];
    }
}
void identityM8(M8 *Mat)//identity matrix 8*8
{
    int i;
    for(i = 0; i < 8; i++)
    {
        (*Mat).M[i] = idM8[i];
    }
}
void identityM16(M16 *Mat)//identity matrix 16*16
{
    int i;
    for(i = 0; i < 16; i++)
    {
        (*Mat).M[i] = idM16[i];
    }
}
void identityM32(M32 *Mat)//identity matrix 32*32
{
    int i;
    for(i = 0; i < 32; i++)
    {
        (*Mat).M[i] = idM32[i];
    }
}
void identityM64(M64 *Mat)//identity matrix 64*64
{
    int i;
    for(i = 0; i < 64; i++)
    {
        (*Mat).M[i] = idM64[i];
    }
}
void identityM128(M128 *Mat)//identity matrix 128*128
{
    int i;
    for(i = 0; i < 64; i++)
    {
        (*Mat).M[i][0] = idM64[i];
        (*Mat).M[i][1] = 0;
    }
    for(i = 64; i < 128; i++)
    {
        (*Mat).M[i][0] = 0;
        (*Mat).M[i][1] = idM64[i-64];
    }
}
void randV4(V4 *Vec)//randomize Vector 4*1
{
    InitRandom((randseed)^matrixseed);
    (*Vec).V = cus_random() & 0x0f;
}
void randV8(V8 *Vec)//randomize Vector 8*1
{
    InitRandom((randseed)^matrixseed);
    (*Vec).V = cus_random();
}
void randV16(V16 *Vec)//randomize Vector 16*1
{
    InitRandom((randseed)^matrixseed);
    (*Vec).V = cus_random();
}
void randV32(V32 *Vec)//randomize Vector 32*1
{
    uint16_t *v = (uint16_t*)&((*Vec).V);
    InitRandom((randseed)^matrixseed);
    *(v+1) = cus_random();
    *v = cus_random();
}
void randV64(V64 *Vec)//randomize Vector 64*1
{
    uint16_t *v = (uint16_t*)&((*Vec).V);
    InitRandom((randseed)^matrixseed);
    *(v+3) = cus_random();
    *(v+2) = cus_random();
    *(v+1) = cus_random();
    *v = cus_random();
}
void randV128(V128 *Vec)//randomize Vector 128*1
{
    uint16_t *v = (uint16_t*)&((*Vec).V[0]);
    InitRandom((randseed)^matrixseed);
    *(v+3) = cus_random();
    *(v+2) = cus_random();
    *(v+1) = cus_random();
    *v = cus_random();
    v = (uint16_t*)&((*Vec).V[1]);
    *(v+3) = cus_random();
    *(v+2) = cus_random();
    *(v+1) = cus_random();
    *v = cus_random();
}
void printM4(M4 Mat)//printf Matrix 4*4
{
    int i;
    for(i = 0; i < 4; i++)
    {
        printf("0x%x\n", Mat.M[i]);
    }
}
void printM8(M8 Mat)//printf Matrix 8*8
{
    int i;
    for(i = 0; i < 8; i++)
    {
        printf("0x%x\n", Mat.M[i]);
    }
}
void printM16(M16 Mat)//printf Matrix 16*16
{
    int i;
    for(i = 0; i < 16; i++)
    {
        printf("0x%x\n", Mat.M[i]);
    }
}
void printM32(M32 Mat)//printf Matrix 32*32
{
    int i;
    for(i = 0; i < 32; i++)
    {
        printf("0x%x\n", Mat.M[i]);
    }
}
void printM64(M64 Mat)//printf Matrix 64*64
{
    int i;
    for(i = 0; i < 64; i++)
    {
        //printf("0x%llx\n", Mat.M[i]);
    }
}
void printM128(M128 Mat)//printf Matrix 128*128
{
    int i;
    for(i = 0; i < 128; i++)
    {
        //printf("0x%llx ", Mat.M[i][0]);
        //printf("0x%llx\n", Mat.M[i][1]);
    }
}
void printV4(V4 Vec)//printf Vector 4*1
{
    printf("0x%x\n", Vec.V);
}
void printV8(V8 Vec)//printf Vector 8*1
{
    printf("0x%x\n", Vec.V);
}
void printV16(V16 Vec)//printf Vector 16*1
{
    printf("0x%x\n", Vec.V);
}
void printV32(V32 Vec)//printf Vector 32*1
{
    printf("0x%x\n", Vec.V);
}
void printV64(V64 Vec)//printf Vector 64*1
{
    //printf("0x%llx\n", Vec.V);
}
void printV128(V128 Vec)//printf Vector 128*1
{
    //printf("0x%llx ", Vec.V[0]);
    //printf("0x%llx\n", Vec.V[1]);
}
void copyM4(M4 Mat1, M4 *Mat2)
{
    int i;
    for(i = 0; i < 4; i++)
    {
        (*Mat2).M[i] = Mat1.M[i];
    }
}
void copyM8(M8 Mat1, M8 *Mat2)
{
    int i;
    for(i = 0; i < 8; i++)
    {
        (*Mat2).M[i] = Mat1.M[i];
    }
}
void copyM16(M16 Mat1, M16 *Mat2)
{
    int i;
    for(i = 0; i < 16; i++)
    {
        (*Mat2).M[i] = Mat1.M[i];
    }
}
void copyM32(M32 Mat1, M32 *Mat2)
{
    int i;
    for(i = 0; i < 32; i++)
    {
        (*Mat2).M[i] = Mat1.M[i];
    }
}
void copyM64(M64 Mat1, M64 *Mat2)
{
    int i;
    for(i = 0; i < 64; i++)
    {
        (*Mat2).M[i] = Mat1.M[i];
    }
}
void copyM128(M128 Mat1, M128 *Mat2)
{
    int i;
    for(i = 0; i < 128; i++)
    {
        (*Mat2).M[i][0] = Mat1.M[i][0];
        (*Mat2).M[i][1] = Mat1.M[i][1];
    }
}
int isequalM4(M4 Mat1, M4 Mat2)
{
    int i;
    int flag = 1;
    for(i = 0; i < 4; i++)
    {
        if(Mat1.M[i] != Mat2.M[i])
        {
            flag = 0;
            break;
        }
    }
    return flag;
}
int isequalM8(M8 Mat1, M8 Mat2)
{
    int i;
    int flag = 1;
    for(i = 0; i < 8; i++)
    {
        if(Mat1.M[i] != Mat2.M[i])
        {
            flag = 0;
            break;
        }
    }
    return flag;
}
int isequalM16(M16 Mat1, M16 Mat2)
{
    int i;
    int flag = 1;
    for(i = 0; i < 16; i++)
    {
        if(Mat1.M[i] != Mat2.M[i])
        {
            flag = 0;
            break;
        }
    }
    return flag;
}
int isequalM32(M32 Mat1, M32 Mat2)
{
    int i;
    int flag = 1;
    for(i = 0; i < 32; i++)
    {
        if(Mat1.M[i] != Mat2.M[i])
        {
            flag = 0;
            break;
        }
    }
    return flag;
}
int isequalM64(M64 Mat1, M64 Mat2)
{
    int i;
    int flag = 1;
    for(i = 0; i < 64; i++)
    {
        if(Mat1.M[i] != Mat2.M[i])
        {
            flag = 0;
            break;
        }
    }
    return flag;
}
int isequalM128(M128 Mat1, M128 Mat2)
{
    int i;
    int flag = 1;
    for(i = 0; i < 128; i++)
    {
        if(Mat1.M[i][0] != Mat2.M[i][0])
        {
            flag = 0;
            break;
        }
        if(Mat1.M[i][1] != Mat2.M[i][1])
        {
            flag = 0;
            break;
        }
    }
    return flag;
}
int isequalV4(V4 Vec1, V4 Vec2)
{
    int flag = 1;
    if(Vec1.V != Vec2.V) flag = 0;
    return flag;
}
int isequalV8(V8 Vec1, V8 Vec2)
{
    int flag = 1;
    if(Vec1.V != Vec2.V) flag = 0;
    return flag;
}
int isequalV16(V16 Vec1, V16 Vec2)
{
    int flag = 1;
    if(Vec1.V != Vec2.V) flag = 0;
    return flag;
}
int isequalV32(V32 Vec1, V32 Vec2)
{
    int flag = 1;
    if(Vec1.V != Vec2.V) flag = 0;
    return flag;
}
int isequalV64(V64 Vec1, V64 Vec2)
{
    int flag = 1;
    if(Vec1.V != Vec2.V) flag = 0;
    return flag;
}
int isequalV128(V128 Vec1, V128 Vec2)
{
    int flag = 1;
    if(Vec1.V[0] != Vec2.V[0]) flag = 0;
    if(Vec1.V[1] != Vec2.V[1]) flag = 0;
    return flag;
}
int readbitM4(M4 Mat, int i, int j)//read one bit in a matrix, i in n rows, j in n columns, i,j: 0-3
{
    if((Mat.M[i] & idM4[j]) == idM4[j]) return 1;
    else return 0;
}
int readbitM8(M8 Mat, int i, int j)//read one bit in a matrix, i in n rows, j in n columns, i,j: 0-7
{
    if((Mat.M[i] & idM8[j]) == idM8[j]) return 1;
    else return 0;
}
int readbitM16(M16 Mat, int i, int j)//read one bit in a matrix, i in n rows, j in n columns, i,j: 0-15
{
    if((Mat.M[i] & idM16[j]) == idM16[j]) return 1;
    else return 0;
}
int readbitM32(M32 Mat, int i, int j)//read one bit in a matrix, i in n rows, j in n columns, i,j: 0-31
{
    if((Mat.M[i] & idM32[j]) == idM32[j]) return 1;
    else return 0;
}
int readbitM64(M64 Mat, int i, int j)//read one bit in a matrix, i in n rows, j in n columns, i,j: 0-63
{
    if((Mat.M[i] & idM64[j]) == idM64[j]) return 1;
    else return 0;
}
int readbitM128(M128 Mat, int i, int j)//read one bit in a matrix, i in n rows, j in n columns, i,j: 0-127
{
    if(j < 64)
    {
        if((Mat.M[i][0] & idM64[j]) == idM64[j]) return 1;
        else return 0;
    }
    else
    {
        if((Mat.M[i][1] & idM64[j - 64]) == idM64[j - 64]) return 1;
        else return 0;
    }
}
void flipbitM4(M4 *Mat, int i, int j)//flip (i, j) bit in a matrix
{
    (*Mat).M[i] ^= idM4[j];
}
void flipbitM8(M8 *Mat, int i, int j)//flip (i, j) bit in a matrix
{
    (*Mat).M[i] ^= idM8[j];
}
void flipbitM16(M16 *Mat, int i, int j)//flip (i, j) bit in a matrix
{
    (*Mat).M[i] ^= idM16[j];
}
void flipbitM32(M32 *Mat, int i, int j)//flip (i, j) bit in a matrix
{
    (*Mat).M[i] ^= idM32[j];
}
void flipbitM64(M64 *Mat, int i, int j)//flip (i, j) bit in a matrix
{
    (*Mat).M[i] ^= idM64[j];
}
void flipbitM128(M128 *Mat, int i, int j)//flip (i, j) bit in a matrix
{
    if(j <64)
    {
        (*Mat).M[i][0] ^= idM64[j];
    }
    else
    {
        (*Mat).M[i][1] ^= idM64[j - 64];
    }
}
void setbitM4(M4 *Mat, int i, int j, int bit)//set (i, j) bit in a matrix, bit = 0/1
{
    if(readbitM4(*Mat, i, j) == bit) return;
    else flipbitM4(Mat, i, j);
}
void setbitM8(M8 *Mat, int i, int j, int bit)//set (i, j) bit in a matrix, bit = 0/1
{
    if(readbitM8(*Mat, i, j) == bit) return;
    else flipbitM8(Mat, i, j);
}
void setbitM16(M16 *Mat, int i, int j, int bit)//set (i, j) bit in a matrix, bit = 0/1
{
    if(readbitM16(*Mat, i, j) == bit) return;
    else flipbitM16(Mat, i, j);
}
void setbitM32(M32 *Mat, int i, int j, int bit)//set (i, j) bit in a matrix, bit = 0/1
{
    if(readbitM32(*Mat, i, j) == bit) return;
    else flipbitM32(Mat, i, j);
}
void setbitM64(M64 *Mat, int i, int j, int bit)//set (i, j) bit in a matrix, bit = 0/1
{
    if(readbitM64(*Mat, i, j) == bit) return;
    else flipbitM64(Mat, i, j);
}
void setbitM128(M128 *Mat, int i, int j, int bit)//set (i, j) bit in a matrix, bit = 0/1
{
    if(readbitM128(*Mat, i, j) == bit) return;
    else flipbitM128(Mat, i, j);
}
int isinvertM4(M4 Mat)//Invertible Matrix?
{
    int i, j, k;
    uint8_t temp;
    int flag;
    for(i = 0; i < 4; i++)
    {
        if((Mat.M[i] & idM4[i]) == idM4[i])
        {
            for(j = i + 1; j < 4; j++)
            {
                if((Mat.M[j] & idM4[i]) == idM4[i])
                {
                    Mat.M[j] ^= Mat.M[i];
                }
            }
        }
        else
        {
            flag = 1;
            for(j = i + 1; j < 4; j++)
            {
                if((Mat.M[j] & idM4[i]) == idM4[i])
                {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;
                    flag = 0;
                    break;
                }
            }
            if(flag) return 0;
            for(k = i + 1; k < 4; k++)
            {
                if((Mat.M[k] & idM4[i]) == idM4[i])
                {
                    Mat.M[k] ^= Mat.M[i];
                }
            }
        }
    }
    if(Mat.M[3] == idM4[3]) return 1;
    else return 0;
}
int isinvertM8(M8 Mat)//Invertible Matrix?
{
    int i, j, k;
    uint8_t temp;
    int flag;
    for(i = 0; i < 8; i++)
    {
        if((Mat.M[i] & idM8[i]) == idM8[i])
        {
            for(j = i + 1; j < 8; j++)
            {
                if((Mat.M[j] & idM8[i]) == idM8[i])
                {
                    Mat.M[j] ^= Mat.M[i];
                }
            }
        }
        else
        {
            flag = 1;
            for(j = i + 1; j < 8; j++)
            {
                if((Mat.M[j] & idM8[i]) == idM8[i])
                {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;
                    flag = 0;
                    break;
                }
            }
            if(flag) return 0;
            for(k = i + 1; k < 8; k++)
            {
                if((Mat.M[k] & idM8[i]) == idM8[i])
                {
                    Mat.M[k] ^= Mat.M[i];
                }
            }
        }
    }
    if(Mat.M[7] == idM8[7]) return 1;
    else return 0;
}
int isinvertM16(M16 Mat)//Invertible Matrix?
{
    int i, j, k;
    uint16_t temp;
    int flag;
    for(i = 0; i < 16; i++)
    {
        if((Mat.M[i] & idM16[i]) == idM16[i])
        {
            for(j = i + 1; j < 16; j++)
            {
                if((Mat.M[j] & idM16[i]) == idM16[i])
                {
                    Mat.M[j] ^= Mat.M[i];
                }
            }
        }
        else
        {
            flag = 1;
            for(j = i + 1; j < 16; j++)
            {
                if((Mat.M[j] & idM16[i]) == idM16[i])
                {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;
                    flag = 0;
                    break;
                }
            }
            if(flag) return 0;
            for(k = i + 1; k < 16; k++)
            {
                if((Mat.M[k] & idM16[i]) == idM16[i])
                {
                    Mat.M[k] ^= Mat.M[i];
                }
            }
        }
    }
    if(Mat.M[15] == idM16[15]) return 1;
    else return 0;
}
int isinvertM32(M32 Mat)//Invertible Matrix?
{
    int i, j, k;
    uint32_t temp;
    int flag;
    for(i = 0; i < 32; i++)
    {
        if((Mat.M[i] & idM32[i]) == idM32[i])
        {
            for(j = i + 1; j < 32; j++)
            {
                if((Mat.M[j] & idM32[i]) == idM32[i])
                {
                    Mat.M[j] ^= Mat.M[i];
                }
            }
        }
        else
        {
            flag = 1;
            for(j = i + 1; j < 32; j++)
            {
                if((Mat.M[j] & idM32[i]) == idM32[i])
                {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;
                    flag = 0;
                    break;
                }
            }
            if(flag) return 0;
            for(k = i + 1; k < 32; k++)
            {
                if((Mat.M[k] & idM32[i]) == idM32[i])
                {
                    Mat.M[k] ^= Mat.M[i];
                }
            }
        }
    }
    if(Mat.M[31] == idM32[31]) return 1;
    else return 0;
}
int isinvertM64(M64 Mat)//Invertible Matrix?
{
    int i, j, k;
    uint64_t temp;
    int flag;
    for(i = 0; i < 64; i++)
    {
        if((Mat.M[i] & idM64[i]) == idM64[i])
        {
            for(j = i + 1; j < 64; j++)
            {
                if((Mat.M[j] & idM64[i]) == idM64[i])
                {
                    Mat.M[j] ^= Mat.M[i];
                }
            }
        }
        else
        {
            flag = 1;
            for(j = i + 1; j < 64; j++)
            {
                if((Mat.M[j] & idM64[i]) == idM64[i])
                {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;
                    flag = 0;
                    break;
                }
            }
            if(flag) return 0;
            for(k = i + 1; k < 64; k++)
            {
                if((Mat.M[k] & idM64[i]) == idM64[i])
                {
                    Mat.M[k] ^= Mat.M[i];
                }
            }
        }
    }
    if(Mat.M[63] == idM64[63]) return 1;
    else return 0;
}
int isinvertM128(M128 Mat)//Invertible Matrix?
{
    int i, j, k;
    uint64_t temp[2];
    int flag;
    for(i = 0; i < 64; i++)
    {
        if((Mat.M[i][0] & idM64[i]) == idM64[i])
        {
            for(j = i + 1; j < 128; j++)
            {
                if((Mat.M[j][0] & idM64[i]) == idM64[i])
                {
                    Mat.M[j][0] ^= Mat.M[i][0];
                    Mat.M[j][1] ^= Mat.M[i][1];
                }
            }
        }
        else
        {
            flag = 1;
            for(j = i + 1; j < 128; j++)
            {
                if((Mat.M[j][0] & idM64[i]) == idM64[i])
                {
                    temp[0] = Mat.M[i][0];
                    Mat.M[i][0] = Mat.M[j][0];
                    Mat.M[j][0] = temp[0];

                    temp[1] = Mat.M[i][1];
                    Mat.M[i][1] = Mat.M[j][1];
                    Mat.M[j][1] = temp[1];
                    flag = 0;
                    break;
                }
            }
            if(flag) return 0;
            for(k = i + 1; k < 128; k++)
            {
                if((Mat.M[k][0] & idM64[i]) == idM64[i])
                {
                    Mat.M[k][0] ^= Mat.M[i][0];
                    Mat.M[k][1] ^= Mat.M[i][1];
                }
            }
        }
    }
    for(i = 64; i < 128;i++)
    {
        if((Mat.M[i][1] & idM64[i-64]) == idM64[i-64])
        {
            for(j = i + 1; j < 128; j++)
            {
                if((Mat.M[j][1] & idM64[i-64]) == idM64[i-64])
                {
                    Mat.M[j][1] ^= Mat.M[i][1];
                }
            }
        }
        else
        {
            flag = 1;
            for(j = i + 1; j < 128; j++)
            {
                if((Mat.M[j][1] & idM64[i-64]) == idM64[i-64])
                {
                    temp[1] = Mat.M[i][1];
                    Mat.M[i][1] = Mat.M[j][1];
                    Mat.M[j][1] = temp[1];
                    flag = 0;
                    break;
                }
            }
            if(flag) return 0;
            for(k = i + 1; k < 128; k++)
            {
                if((Mat.M[k][1] & idM64[i-64]) == idM64[i-64])
                {
                    Mat.M[k][1] ^= Mat.M[i][1];
                }
            }
        }
    }
    if(Mat.M[127][1] == idM64[63]) return 1;
    else return 0;
}
void invsM4(M4 Mat, M4 *Mat_inv)//compute the 4*4 inverse matrix
{
    int i, j, k;
    uint8_t temp;
    identityM4(Mat_inv);
    for(i = 0; i < 4; i++)
    {
        if((Mat.M[i] & idM4[i]) == idM4[i])
        {
            for(j = i + 1; j < 4; j++)
            {
                if((Mat.M[j] & idM4[i]) == idM4[i])
                {
                    Mat.M[j] ^= Mat.M[i];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        else
        {
            for(j = i + 1; j < 4; j++)
            {
                if((Mat.M[j] & idM4[i]) == idM4[i])
                {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;
                    break;
                }
            }
            for(k = i + 1; k < 4; k++)
            {
                if((Mat.M[k] & idM4[i]) == idM4[i])
                {
                    Mat.M[k] ^= Mat.M[i];
                    (*Mat_inv).M[k] ^= (*Mat_inv).M[i];
                }
            }
        }
    }
    for(i = 3; i >= 0; i--)
    {
        for(j = i - 1; j >= 0; j--)
        {
            if((Mat.M[j] & idM4[i]) == idM4[i])
            {
                Mat.M[j] ^= Mat.M[i];
                (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
            }
        }
    }
}
void invsM8(M8 Mat, M8 *Mat_inv)//compute the 8*8 inverse matrix
{
    int i, j, k;
    uint8_t temp;
    identityM8(Mat_inv);
    for(i = 0; i < 8; i++)
    {
        if((Mat.M[i] & idM8[i]) == idM8[i])
        {
            for(j = i + 1; j < 8; j++)
            {
                if((Mat.M[j] & idM8[i]) == idM8[i])
                {
                    Mat.M[j] ^= Mat.M[i];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        else
        {
            for(j = i + 1; j < 8; j++)
            {
                if((Mat.M[j] & idM8[i]) == idM8[i])
                {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;
                    break;
                }
            }
            for(k = i + 1; k < 8; k++)
            {
                if((Mat.M[k] & idM8[i]) == idM8[i])
                {
                    Mat.M[k] ^= Mat.M[i];
                    (*Mat_inv).M[k] ^= (*Mat_inv).M[i];
                }
            }
        }
    }
    for(i = 7; i >= 0; i--)
    {
        for(j = i - 1; j >= 0; j--)
        {
            if((Mat.M[j] & idM8[i]) == idM8[i])
            {
                Mat.M[j] ^= Mat.M[i];
                (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
            }
        }
    }
}
void invsM16(M16 Mat, M16 *Mat_inv)//compute the 16*16 inverse matrix
{
    int i, j, k;
    uint16_t temp;
    identityM16(Mat_inv);
    for(i = 0; i < 16; i++)
    {
        if((Mat.M[i] & idM16[i]) == idM16[i])
        {
            for(j = i + 1; j < 16; j++)
            {
                if((Mat.M[j] & idM16[i]) == idM16[i])
                {
                    Mat.M[j] ^= Mat.M[i];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        else
        {
            for(j = i + 1; j < 16; j++)
            {
                if((Mat.M[j] & idM16[i]) == idM16[i])
                {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;
                    break;
                }
            }
            for(k = i + 1; k < 16; k++)
            {
                if((Mat.M[k] & idM16[i]) == idM16[i])
                {
                    Mat.M[k] ^= Mat.M[i];
                    (*Mat_inv).M[k] ^= (*Mat_inv).M[i];
                }
            }
        }
    }
    for(i = 15; i >= 0; i--)
    {
        for(j = i - 1; j >= 0; j--)
        {
            if((Mat.M[j] & idM16[i]) == idM16[i])
            {
                Mat.M[j] ^= Mat.M[i];
                (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
            }
        }
    }
}
void invsM32(M32 Mat, M32 *Mat_inv)//compute the 32*32 inverse matrix
{
    int i, j, k;
    uint32_t temp;
    identityM32(Mat_inv);
    for(i = 0; i < 32; i++)
    {
        if((Mat.M[i] & idM32[i]) == idM32[i])
        {
            for(j = i + 1; j < 32; j++)
            {
                if((Mat.M[j] & idM32[i]) == idM32[i])
                {
                    Mat.M[j] ^= Mat.M[i];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        else
        {
            for(j = i + 1; j < 32; j++)
            {
                if((Mat.M[j] & idM32[i]) == idM32[i])
                {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;
                    break;
                }
            }
            for(k = i + 1; k < 32; k++)
            {
                if((Mat.M[k] & idM32[i]) == idM32[i])
                {
                    Mat.M[k] ^= Mat.M[i];
                    (*Mat_inv).M[k] ^= (*Mat_inv).M[i];
                }
            }
        }
    }
    for(i = 31; i >= 0; i--)
    {
        for(j = i - 1; j >= 0; j--)
        {
            if((Mat.M[j] & idM32[i]) == idM32[i])
            {
                Mat.M[j] ^= Mat.M[i];
                (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
            }
        }
    }
}
void invsM64(M64 Mat, M64 *Mat_inv)//compute the 64*64 inverse matrix
{
    int i, j, k;
    uint64_t temp;
    identityM64(Mat_inv);
    for(i = 0; i < 64; i++)
    {
        if((Mat.M[i] & idM64[i]) == idM64[i])
        {
            for(j = i + 1; j < 64; j++)
            {
                if((Mat.M[j] & idM64[i]) == idM64[i])
                {
                    Mat.M[j] ^= Mat.M[i];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        else
        {
            for(j = i + 1; j < 64; j++)
            {
                if((Mat.M[j] & idM64[i]) == idM64[i])
                {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;
                    break;
                }
            }
            for(k = i + 1; k < 64; k++)
            {
                if((Mat.M[k] & idM64[i]) == idM64[i])
                {
                    Mat.M[k] ^= Mat.M[i];
                    (*Mat_inv).M[k] ^= (*Mat_inv).M[i];
                }
            }
        }
    }
    for(i = 63; i >= 0; i--)
    {
        for(j = i - 1; j >= 0; j--)
        {
            if((Mat.M[j] & idM64[i]) == idM64[i])
            {
                Mat.M[j] ^= Mat.M[i];
                (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
            }
        }
    }
}
void invsM128(M128 Mat, M128 *Mat_inv)//compute the 128*128 inverse matrix
{
    int i, j, k;
    uint64_t temp[2];
    identityM128(Mat_inv);
    for(i = 0; i < 64; i++)
    {
        if((Mat.M[i][0] & idM64[i]) == idM64[i])
        {
            for(j = i + 1; j < 128; j++)
            {
                if((Mat.M[j][0] & idM64[i]) == idM64[i])
                {
                    Mat.M[j][0] ^= Mat.M[i][0];
                    Mat.M[j][1] ^= Mat.M[i][1];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                }
            }
        }
        else
        {
            for(j = i + 1; j < 128; j++)
            {
                if((Mat.M[j][0] & idM64[i]) == idM64[i])
                {
                    temp[0] = Mat.M[i][0];
                    Mat.M[i][0] = Mat.M[j][0];
                    Mat.M[j][0] = temp[0];

                    temp[1] = Mat.M[i][1];
                    Mat.M[i][1] = Mat.M[j][1];
                    Mat.M[j][1] = temp[1];

                    temp[0] = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = (*Mat_inv).M[j][0];
                    (*Mat_inv).M[j][0] = temp[0];

                    temp[1] = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = (*Mat_inv).M[j][1];
                    (*Mat_inv).M[j][1] = temp[1];
                    break;
                }
            }
            for(k = i + 1; k < 128; k++)
            {
                if((Mat.M[k][0] & idM64[i]) == idM64[i])
                {
                    Mat.M[k][0] ^= Mat.M[i][0];
                    Mat.M[k][1] ^= Mat.M[i][1];

                    (*Mat_inv).M[k][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[k][1] ^= (*Mat_inv).M[i][1];
                }
            }
        }
    }
    for(i = 64; i < 128; i++)
    {
        if((Mat.M[i][1] & idM64[i-64]) == idM64[i-64])
        {
            for(j = i + 1; j < 128; j++)
            {
                if((Mat.M[j][1] & idM64[i-64]) == idM64[i-64])
                {
                    Mat.M[j][1] ^= Mat.M[i][1];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                }
            }
        }
        else
        {
            for(j = i + 1; j < 128; j++)
            {
                if((Mat.M[j][1] & idM64[i-64]) == idM64[i-64])
                {
                    temp[1] = Mat.M[i][1];
                    Mat.M[i][1] = Mat.M[j][1];
                    Mat.M[j][1] = temp[1];

                    temp[0] = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = (*Mat_inv).M[j][0];
                    (*Mat_inv).M[j][0] = temp[0];

                    temp[1] = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = (*Mat_inv).M[j][1];
                    (*Mat_inv).M[j][1] = temp[1];
                    break;
                }
            }
            for(k = i + 1; k < 128; k++)
            {
                if((Mat.M[k][1] & idM64[i-64]) == idM64[i-64])
                {
                    Mat.M[k][1] ^= Mat.M[i][1];

                    (*Mat_inv).M[k][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[k][1] ^= (*Mat_inv).M[i][1];
                }
            }
        }
    }
    for(i = 127; i >= 64; i--)
    {
        for(j = i - 1; j >= 0; j--)
        {
            if((Mat.M[j][1] & idM64[i-64]) == idM64[i-64])
            {
                Mat.M[j][1] ^= Mat.M[i][1];
                (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
            }
        }
    }
    for(i = 63; i >= 0; i--)
    {
        for(j = i - 1; j >= 0; j--)
        {
            if((Mat.M[j][0] & idM64[i]) == idM64[i])
            {
                Mat.M[j][0] ^= Mat.M[i][0];
                (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
            }
        }
    }
}
uint8_t affineU4(Aff4 aff, uint8_t arr)//4bits affine transformation
{
    V4 mul_vec, ans_vec;
    mul_vec.V = arr;
    MatMulVecM4(aff.Mat, mul_vec, &ans_vec);//mul
    return ans_vec.V ^ aff.Vec.V;//add
}
uint8_t affineU8(Aff8 aff, uint8_t arr)//8bits affine transformation
{
    V8 mul_vec, ans_vec;
    mul_vec.V = arr;
    MatMulVecM8(aff.Mat, mul_vec, &ans_vec);//mul
    return ans_vec.V ^ aff.Vec.V;//add
}
uint16_t affineU16(Aff16 aff, uint16_t arr)//16bits affine transformation
{
    V16 mul_vec, ans_vec;
    mul_vec.V = arr;
    MatMulVecM16(aff.Mat, mul_vec, &ans_vec);//mul
    return ans_vec.V ^ aff.Vec.V;//add
}
uint32_t affineU32(Aff32 aff, uint32_t arr)//32bits affine transformation
{
    V32 mul_vec, ans_vec;
    mul_vec.V = arr;
    MatMulVecM32(aff.Mat, mul_vec, &ans_vec);//mul
    return ans_vec.V ^ aff.Vec.V;//add
}
uint64_t affineU64(Aff64 aff, uint64_t arr)//64bits affine transformation
{
    V64 mul_vec, ans_vec;
    mul_vec.V = arr;
    MatMulVecM64(aff.Mat, mul_vec, &ans_vec);//mul
    return ans_vec.V ^ aff.Vec.V;//add
}
void affineU128(Aff128 aff, uint64_t arr[], uint64_t ans[])//128bits affine transformation
{
    V128 mul_vec, ans_vec;
    mul_vec.V[0] = arr[0];
    mul_vec.V[1] = arr[1];
    MatMulVecM128(aff.Mat, mul_vec, &ans_vec);//mul
    ans[0] = ans_vec.V[0] ^ aff.Vec.V[0];//add
    ans[1] = ans_vec.V[1] ^ aff.Vec.V[1];
}
int xorU4(uint8_t n)// 4bits internal xor
{
    if(xor[n]) return 1;
    else return 0;
}
int xorU8(uint8_t n)// uint8_t internal xor
{
    if(xor[n]) return 1;
    else return 0;
}
int xorU16(uint16_t n)// uint16_t internal xor
{
    uint8_t temp = 0;
    uint8_t* u = (uint8_t*)&n;
    temp = (*u) ^ (*(u+1));
    if(xorU8(temp)) return 1;
    else return 0;
}
int xorU32(uint32_t n)// uint32_t internal xor
{
    uint16_t temp = 0;
    uint16_t* u = (uint16_t*)&n;
    temp = (*u) ^ (*(u+1));
    if(xorU16(temp)) return 1;
    else return 0;
}
int xorU64(uint64_t n)// uint64_t internal xor
{
    uint32_t temp = 0;
    uint32_t* u = (uint32_t*)&n;
    temp = (*u) ^ (*(u+1));
    if(xorU32(temp)) return 1;
    else return 0;
}
int xorU128(uint64_t n[])// uint128_t internal xor
{
    uint64_t temp = 0;
    temp = n[0] ^ n[1];
    if(xorU64(temp)) return 1;
    else return 0;
}
int HWU4(uint8_t n)// 4bits HW
{
    return HW[n];
}
int HWU8(uint8_t n)// uint8_t HW
{
    return HW[n];
}
int HWU16(uint16_t n)// uint16_t HW
{
    uint8_t* u = (uint8_t*)&n;
    return HWU8(*u) + HWU8(*(u+1));
}
int HWU32(uint32_t n)// uint32_t HW
{
    uint16_t* u = (uint16_t*)&n;
    return HWU16(*u) + HWU16(*(u+1));
}
int HWU64(uint64_t n)// uint64_t HW
{
    uint32_t* u = (uint32_t*)&n;
    return HWU32(*u) + HWU32(*(u+1));
}
int HWU128(uint64_t n[])// uint128_t HW
{
    return HWU64(n[0]) + HWU64(n[1]);
}
void printU8(uint8_t n)//printf uint8_t
{
    printf("0x%x\n", n);
}
void printU16(uint16_t n)//printf uint16_t
{
    printf("0x%x\n", n);
}
void printU32(uint32_t n)//printf uint32_t
{
    printf("0x%x\n", n);
}
void printU64(uint64_t n)//printf uint64_t
{
    //printf("0x%x\n", n);
}
void printU128(uint64_t n[])//printf uint128_t
{
    //printf("0x%x ", n[0]);
    //printf("0x%x\n", n[1]);
}
void printbitM4(M4 Mat)//printf Matrix 4*4 in the form of bits 
{
    int i, j;
    uint8_t temp;
    for(i = 0; i < 4; i++)
    {
        temp = Mat.M[i];
        for(j = 0; j < 4; j++)
        {
            if(temp & 0x08) printf("%d ", 1);
            else printf("%d ", 0);
            temp = temp << 1;
        }
        printf("\n");
    }
    printf("\n");
}
void printbitM8(M8 Mat)//printf Matrix 8*8 in the form of bits 
{
    int i, j;
    uint8_t temp;
    for(i = 0; i < 8; i++)
    {
        temp = Mat.M[i];
        for(j = 0; j < 8; j++)
        {
            if(temp & 0x80) printf("%d ", 1);
            else printf("%d ", 0);
            temp = temp << 1;
        }
        printf("\n");
    }
    printf("\n");
}
void printbitM16(M16 Mat)//printf Matrix 16*16 in the form of bits 
{
    int i, j;
    uint16_t temp;
    for(i = 0; i < 16; i++)
    {
        temp = Mat.M[i];
        for(j = 0; j < 16; j++)
        {
            if(temp & 0x8000) printf("%d ", 1);
            else printf("%d ", 0);
            temp = temp << 1;
        }
        printf("\n");
    }
    printf("\n");
}
void printbitM32(M32 Mat)//printf Matrix 32*32 in the form of bits 
{
    int i, j;
    uint32_t temp;
    for(i = 0; i < 32; i++)
    {
        temp = Mat.M[i];
        for(j = 0; j < 32; j++)
        {
            if(temp & 0x80000000) printf("%d ", 1);
            else printf("%d ", 0);
            temp = temp << 1;
        }
        printf("\n");
    }
    printf("\n");
}
void printbitM64(M64 Mat)//printf Matrix 64*64 in the form of bits 
{
    int i, j;
    uint64_t temp;
    for(i = 0; i < 64; i++)
    {
        temp = Mat.M[i];
        for(j = 0; j < 64; j++)
        {
            if(temp & 0x8000000000000000) printf("%d ", 1);
            else printf("%d ", 0);
            temp = temp << 1;
        }
        printf("\n");
    }
    printf("\n");
}
void printbitM128(M128 Mat)//printf Matrix 128*128 in the form of bits 
{
    int i, j;
    uint64_t temp;
    for(i = 0; i < 128; i++)
    {
        temp = Mat.M[i][0];
        for(j = 0; j < 64; j++)
        {
            if(temp & 0x8000000000000000) printf("%d ", 1);
            else printf("%d ", 0);
            temp = temp << 1;
        }
        temp = Mat.M[i][1];
        for(j = 0; j < 64; j++)
        {
            if(temp & 0x8000000000000000) printf("%d ", 1);
            else printf("%d ", 0);
            temp = temp << 1;
        }
        printf("\n");
    }
    printf("\n");
}
void VecAddVecV4(V4 Vec1, V4 Vec2, V4 *Vec)
{
    (*Vec).V = Vec1.V ^ Vec2.V;
}
void VecAddVecV8(V8 Vec1, V8 Vec2, V8 *Vec)
{
    (*Vec).V = Vec1.V ^ Vec2.V;
}
void VecAddVecV16(V16 Vec1, V16 Vec2, V16 *Vec)
{
    (*Vec).V = Vec1.V ^ Vec2.V;
}
void VecAddVecV32(V32 Vec1, V32 Vec2, V32 *Vec)
{
    (*Vec).V = Vec1.V ^ Vec2.V;
}
void VecAddVecV64(V64 Vec1, V64 Vec2, V64 *Vec)
{
    (*Vec).V = Vec1.V ^ Vec2.V;
}
void VecAddVecV128(V128 Vec1, V128 Vec2, V128 *Vec)
{
    (*Vec).V[0] = Vec1.V[0] ^ Vec2.V[0];
    (*Vec).V[1] = Vec1.V[1] ^ Vec2.V[1];
}
uint8_t MatMulNumM4(M4 Mat, uint8_t n)//matrix * number -> number 4bits
{
    int i;
    uint8_t temp = 0;
    for(i = 0; i < 4; i++)
    {
        if(xorU4(Mat.M[i] & n & 0x0f)) temp ^= idM4[i];
    }
    return temp;
}
uint8_t MatMulNumM8(M8 Mat, uint8_t n)//matrix * number -> number 8bits
{
    int i;
    uint8_t temp = 0;
    for(i = 0; i < 8; i++)
    {
        if(xorU8(Mat.M[i] & n)) temp ^= idM8[i];
    }
    return temp;
}
uint16_t MatMulNumM16(M16 Mat, uint16_t n)//matrix * number -> number 16bits
{
    int i;
    uint16_t temp = 0;
    for(i = 0; i < 16; i++)
    {
        if(xorU16(Mat.M[i] & n)) temp ^= idM16[i];
    }
    return temp;
}
uint32_t MatMulNumM32(M32 Mat, uint32_t n)//matrix * number -> number 32bits
{
    int i;
    uint32_t temp = 0;
    for(i = 0; i < 32; i++)
    {
        if(xorU32(Mat.M[i] & n)) temp ^= idM32[i];
    }
    return temp;
}
uint64_t MatMulNumM64(M64 Mat, uint64_t n)//matrix * number -> number 64bits
{
    int i;
    uint64_t temp = 0;
    for(i = 0; i < 64; i++)
    {
        if(xorU64(Mat.M[i] & n)) temp ^= idM64[i];
    }
    return temp;
}
void MatMulVecM4(M4 Mat, V4 Vec, V4 *ans)//matrix * vector -> vector 4*1
{
    int i;
    initV4(ans);
    for(i = 0; i < 4; i++)
    {
        if(xorU4(Mat.M[i] & Vec.V & 0x0f)) (*ans).V ^= idM4[i];
    }
}
void MatMulVecM8(M8 Mat, V8 Vec, V8 *ans)//matrix * vector -> vector 8*1
{
    int i;
    initV8(ans);
    for(i = 0; i < 8; i++)
    {
        if(xorU8(Mat.M[i] & Vec.V)) (*ans).V ^= idM8[i];
    }
}
void MatMulVecM16(M16 Mat, V16 Vec, V16 *ans)//matrix * vector -> vector 16*1
{
    int i;
    initV16(ans);
    for(i = 0; i < 16; i++)
    {
        if(xorU16(Mat.M[i] & Vec.V)) (*ans).V ^= idM16[i];
    }
}
void MatMulVecM32(M32 Mat, V32 Vec, V32 *ans)//matrix * vector -> vector 32*1
{
    int i;
    initV32(ans);
    for(i = 0; i < 32; i++)
    {
        if(xorU32(Mat.M[i] & Vec.V)) (*ans).V ^= idM32[i];
    }
}
void MatMulVecM64(M64 Mat, V64 Vec, V64 *ans)//matrix * vector -> vector 64*1
{
    int i;
    initV64(ans);
    for(i = 0; i < 64; i++)
    {
        if(xorU64(Mat.M[i] & Vec.V)) (*ans).V ^= idM64[i];
    }
}
void MatMulVecM128(M128 Mat, V128 Vec, V128 *ans)//matrix * vector -> vector 128*1
{
    int i;
    initV128(ans);
    uint64_t temp[2]; 
    for(i = 0; i < 64; i++)
    {
        temp[0] = Mat.M[i][0] & Vec.V[0];
        temp[1] = Mat.M[i][1] & Vec.V[1];
        if(xorU128(temp)) (*ans).V[0] ^= idM64[i];
    }
    for(i = 64; i < 128; i++)
    {
        temp[0] = Mat.M[i][0] & Vec.V[0];
        temp[1] = Mat.M[i][1] & Vec.V[1];
        if(xorU128(temp)) (*ans).V[1] ^= idM64[i-64];
    }
}
void genMatpairM4(M4 *Mat, M4 *Mat_inv)//generate 4*4 invertible matrix and its inverse matrix
{
    int i, j, t, k;
    int p;
    M4 tempMat;
    M4 resultMat;
    uint8_t temp;
    uint8_t trail[16][3];// generate trail
    int flag = 0;
    int times = 0;
    int invertible = 1;
    InitRandom((randseed) ^ matrixseed); 
    identityM4(Mat);
    identityM4(Mat_inv);  
    randM4(&tempMat);
    copyM4(tempMat, &resultMat);
    for(i = 0; i < 4; i++)//diagonal = 1?
    {
        if((tempMat.M[i] & idM4[i]) == idM4[i])
        {
            for(j = i + 1; j < 4; j++)
            {
                if((tempMat.M[j] & idM4[i]) == idM4[i])
                {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        }
        else// swap to find 1
        {
            flag = 1;
            for(j = i + 1; j < 4; j++)
            {
                if((tempMat.M[j] & idM4[i]) == idM4[i])
                {
                    temp = tempMat.M[i];
                    tempMat.M[i] = tempMat.M[j];
                    tempMat.M[j] = temp;

                    flag = 0;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if(flag) //can not find 1 which means not invertible
            {
                invertible = 0;
                if (i < 3)
                {
                    p = i + 1 + cus_random()%(3 - i);//swap
                    temp = tempMat.M[p];
                    tempMat.M[p] = tempMat.M[i];
                    tempMat.M[i] = temp;
                    temp = (*Mat_inv).M[p];
                    (*Mat_inv).M[p] = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = temp;
                    trail[times][0] = 0;
                    trail[times][1] = p;
                    trail[times][2] = i;
                    times++;
                    for(t = i + 1; t < 4; t++)
                    {
                        if(cus_random()%2)
                        {
                            tempMat.M[t] ^= tempMat.M[i];
                            (*Mat_inv).M[t] ^= (*Mat_inv).M[i];
                            trail[times][0] = 1;
                            trail[times][1] = t;
                            trail[times][2] = i;
                            times++;
                        }
                    }
                }
            }
            else //can still contiune
            {
                for(k = i + 1; k < 4; k++)
                {
                    if((tempMat.M[k] & idM4[i]) == idM4[i])
                    {
                        tempMat.M[k] ^= tempMat.M[i];

                        (*Mat_inv).M[k] ^= (*Mat_inv).M[i];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    if(!invertible)//not invertible
    {
        for(t = 3; t >= 0; t--)
        {
            for(j = t - 1; j >= 0; j--)
            {
                if((tempMat.M[j] & idM4[t]) == idM4[t])
                {
                    tempMat.M[j] ^= tempMat.M[t];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[t];
                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }
        
        for(j = times - 1; j >= 0; j--)//generate inverse matrix
        {
            if(trail[j][0])//add
            {
                (*Mat).M[trail[j][1]] ^= (*Mat).M[trail[j][2]];
            }
            else//swap
            {
                temp = (*Mat).M[trail[j][1]];
                (*Mat).M[trail[j][1]] = (*Mat).M[trail[j][2]];
                (*Mat).M[trail[j][2]] = temp;
            }   
        }
    }
    else//invertible 
    {
        for(i = 3; i >= 0; i--)
        {
            for(j = i - 1; j >= 0; j--)
            {
                if((tempMat.M[j] & idM4[i]) == idM4[i])
                {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        copyM4(resultMat, Mat);
    }
}
void genMatpairM8(M8 *Mat, M8 *Mat_inv)//generate 8*8 invertible matrix and its inverse matrix
{
    int i, j, t, k;
    int p;
    M8 tempMat;
    M8 resultMat;
    uint8_t temp;
    uint8_t trail[64][3];// generate trail
    int flag = 0;
    int times = 0;
    int invertible = 1;
    InitRandom((randseed) ^ matrixseed);
    identityM8(Mat);
    identityM8(Mat_inv);
    randM8(&tempMat);
    copyM8(tempMat, &resultMat);
    for(i = 0; i < 8; i++)//diagonal = 1?
    {
        if((tempMat.M[i] & idM8[i]) == idM8[i])
        {
            for(j = i + 1; j < 8; j++)
            {
                if((tempMat.M[j] & idM8[i]) == idM8[i])
                {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];

                    trail[times][0]=1;
                    trail[times][1]=j;
                    trail[times][2]=i;
                    times++;
                }
            }
        }
        else// swap to find 1
        {
            flag = 1;
            for(j = i + 1; j < 8; j++)
            {
                if((tempMat.M[j] & idM8[i]) == idM8[i])
                {
                    temp = tempMat.M[i];
                    tempMat.M[i] = tempMat.M[j];
                    tempMat.M[j] = temp;

                    flag=0;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if(flag) //can not find 1 which means not invertible
            {
                invertible = 0;
                if (i < 7)
                {
                    p = i + 1 + cus_random()%(7 - i);//swap
                    temp = tempMat.M[p];
                    tempMat.M[p] = tempMat.M[i];
                    tempMat.M[i] = temp;
                    temp = (*Mat_inv).M[p];
                    (*Mat_inv).M[p] = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = temp;
                    trail[times][0] = 0;
                    trail[times][1] = p;
                    trail[times][2] = i;
                    times++;
                    for(t = i + 1; t < 8; t++)
                    {
                        if(cus_random()%2)
                        {
                            tempMat.M[t] ^= tempMat.M[i];
                            (*Mat_inv).M[t] ^= (*Mat_inv).M[i];
                            trail[times][0] = 1;
                            trail[times][1] = t;
                            trail[times][2] = i;
                            times++;
                        }
                    }
                }
            }
            else //can still contiune
            {
                for(k = i + 1; k < 8; k++)
                {
                    if((tempMat.M[k] & idM8[i]) == idM8[i])
                    {
                        tempMat.M[k] ^= tempMat.M[i];

                        (*Mat_inv).M[k] ^= (*Mat_inv).M[i];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    if(!invertible)//not invertible
    {
        for(t = 7; t >= 0; t--)
        {
            for(j = t - 1; j >= 0; j--)
            {
                if((tempMat.M[j] & idM8[t]) == idM8[t])
                {
                    tempMat.M[j] ^= tempMat.M[t];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[t];
                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }
        
        for(j = times - 1; j >= 0; j--)//generate inverse matrix
        {
            if(trail[j][0])//add
            {
                (*Mat).M[trail[j][1]] ^= (*Mat).M[trail[j][2]];
            }
            else//swap
            {
                temp = (*Mat).M[trail[j][1]];
                (*Mat).M[trail[j][1]] = (*Mat).M[trail[j][2]];
                (*Mat).M[trail[j][2]] = temp;
            }   
        }
    }
    else//invertible 
    {
        for(i = 7; i >= 0; i--)
        {
            for(j = i - 1; j >= 0; j--)
            {
                if((tempMat.M[j] & idM8[i]) == idM8[i])
                {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        copyM8(resultMat, Mat);
    }
}
void genMatpairM16(M16 *Mat, M16 *Mat_inv)//generate 16*16 invertible matrix and its inverse matrix
{
    int i, j, t, k;
    int p;
    M16 tempMat;
    M16 resultMat;
    uint16_t temp;
    uint8_t trail[256][3];// generate trail
    int flag = 0;
    int times = 0;
    int invertible = 1;
    InitRandom((randseed) ^ matrixseed);
    identityM16(Mat);
    identityM16(Mat_inv);   
    randM16(&tempMat);
    copyM16(tempMat, &resultMat);   
    for(i = 0; i < 16; i++)//diagonal = 1?
    {
        if((tempMat.M[i] & idM16[i]) == idM16[i])
        {
            for(j = i + 1; j < 16; j++)
            {
                if((tempMat.M[j] & idM16[i]) == idM16[i])
                {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        }
        else// swap to find 1
        {
            flag = 1;
            for(j = i + 1; j < 16; j++)
            {
                if((tempMat.M[j] & idM16[i]) == idM16[i])
                {
                    temp = tempMat.M[i];
                    tempMat.M[i] = tempMat.M[j];
                    tempMat.M[j] = temp;

                    flag = 0;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if(flag) //can not find 1 which means not invertible
            {
                invertible = 0;
                if (i < 15)
                {
                    p = i + 1 + cus_random()%(15 - i);//swap
                    temp = tempMat.M[p];
                    tempMat.M[p] = tempMat.M[i];
                    tempMat.M[i] = temp;
                    temp = (*Mat_inv).M[p];
                    (*Mat_inv).M[p] = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = temp;
                    trail[times][0] = 0;
                    trail[times][1] = p;
                    trail[times][2] = i;
                    times++;
                    for(t = i + 1; t < 16; t++)
                    {
                        if(cus_random()%2)
                        {
                            tempMat.M[t] ^= tempMat.M[i];
                            (*Mat_inv).M[t] ^= (*Mat_inv).M[i];
                            trail[times][0] = 1;
                            trail[times][1] = t;
                            trail[times][2] = i;
                            times++;
                        }
                    }
                }
            }
            else //can still contiune
            {
                for(k = i + 1; k < 16; k++)
                {
                    if((tempMat.M[k] & idM16[i]) == idM16[i])
                    {
                        tempMat.M[k] ^= tempMat.M[i];

                        (*Mat_inv).M[k] ^= (*Mat_inv).M[i];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    if(!invertible)//not invertible
    {
        for(t = 15; t >= 0; t--)
        {
            for(j = t - 1; j >= 0; j--)
            {
                if((tempMat.M[j] & idM16[t]) == idM16[t])
                {
                    tempMat.M[j] ^= tempMat.M[t];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[t];
                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }
        
        for(j = times - 1; j >= 0; j--)//generate inverse matrix
        {
            if(trail[j][0])//add
            {
                (*Mat).M[trail[j][1]] ^= (*Mat).M[trail[j][2]];
            }
            else//swap
            {
                temp = (*Mat).M[trail[j][1]];
                (*Mat).M[trail[j][1]] = (*Mat).M[trail[j][2]];
                (*Mat).M[trail[j][2]] = temp;
            }   
        }
    }
    else//invertible 
    {
        for(i = 15; i >= 0; i--)
        {
            for(j = i - 1; j >= 0; j--)
            {
                if((tempMat.M[j] & idM16[i]) == idM16[i])
                {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        copyM16(resultMat, Mat);
    }
}
void genMatpairM32(M32 *Mat, M32 *Mat_inv)//generate 32*32 invertible matrix and its inverse matrix
{
    int i, j, t, k;
    int p;
    M32 tempMat;
    M32 resultMat;
    uint32_t temp;
    uint8_t trail[1024][3];// generate trail
    int flag = 0;
    int times = 0;
    int invertible = 1;
    InitRandom((randseed) ^ matrixseed);
    identityM32(Mat);
    identityM32(Mat_inv);
    randM32(&tempMat);
    copyM32(tempMat, &resultMat);
    for(i = 0; i < 32; i++)//diagonal = 1?
    {
        if((tempMat.M[i] & idM32[i]) == idM32[i])
        {
            for(j = i + 1; j < 32; j++)
            {
                if((tempMat.M[j] & idM32[i]) == idM32[i])
                {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        }
        else// swap to find 1
        {
            flag = 1;
            for(j = i + 1; j < 32; j++)
            {
                if((tempMat.M[j] & idM32[i]) == idM32[i])
                {
                    temp = tempMat.M[i];
                    tempMat.M[i] = tempMat.M[j];
                    tempMat.M[j] = temp;

                    flag=0;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if(flag) //can not find 1 which means not invertible
            {
                invertible = 0;
                if (i < 31)
                {
                    p = i + 1 + cus_random()%(31 - i);//swap
                    temp = tempMat.M[p];
                    tempMat.M[p] = tempMat.M[i];
                    tempMat.M[i] = temp;
                    temp = (*Mat_inv).M[p];
                    (*Mat_inv).M[p] = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = temp;
                    trail[times][0] = 0;
                    trail[times][1] = p;
                    trail[times][2] = i;
                    times++;
                    for(t = i + 1; t < 32; t++)
                    {
                        if(cus_random()%2)
                        {
                            tempMat.M[t] ^= tempMat.M[i];
                            (*Mat_inv).M[t] ^= (*Mat_inv).M[i];
                            trail[times][0] = 1;
                            trail[times][1] = t;
                            trail[times][2] = i;
                            times++;
                        }
                    }
                }
            }
            else //can still contiune
            {
                for(k = i + 1; k < 32; k++)
                {
                    if((tempMat.M[k] & idM32[i]) == idM32[i])
                    {
                        tempMat.M[k] ^= tempMat.M[i];

                        (*Mat_inv).M[k] ^= (*Mat_inv).M[i];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    if(!invertible)//not invertible
    {
        for(t = 31; t >= 0; t--)
        {
            for(j = t - 1; j >= 0; j--)
            {
                if((tempMat.M[j] & idM32[t]) == idM32[t])
                {
                    tempMat.M[j] ^= tempMat.M[t];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[t];
                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }
        
        for(j = times - 1; j >= 0; j--)//generate inverse matrix
        {
            if(trail[j][0])//add
            {
                (*Mat).M[trail[j][1]] ^= (*Mat).M[trail[j][2]];
            }
            else//swap
            {
                temp = (*Mat).M[trail[j][1]];
                (*Mat).M[trail[j][1]] = (*Mat).M[trail[j][2]];
                (*Mat).M[trail[j][2]] = temp;
            }   
        }
    }
    else//invertible 
    {
        for(i = 31; i >= 0; i--)
        {
            for(j = i - 1; j >= 0; j--)
            {
                if((tempMat.M[j] & idM32[i]) == idM32[i])
                {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        copyM32(resultMat, Mat);
    }
}
void genMatpairM64(M64 *Mat, M64 *Mat_inv)//generate 64*64 invertible matrix and its inverse matrix
{
    int i, j, t, k;
    int p;
    M64 tempMat;
    M64 resultMat;
    uint64_t temp;
    uint8_t trail[4096][3];// generate trail
    int flag = 0;
    int times = 0;
    int invertible = 1;
    InitRandom((randseed) ^ matrixseed);
    identityM64(Mat);
    identityM64(Mat_inv);
    randM64(&tempMat);
    copyM64(tempMat, &resultMat);
    for(i = 0; i < 64; i++)//diagonal = 1?
    {
        if((tempMat.M[i] & idM64[i]) == idM64[i])
        {
            for(j = i + 1; j < 64; j++)
            {
                if((tempMat.M[j] & idM64[i]) == idM64[i])
                {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        }
        else// swap to find 1
        {
            flag = 1;
            for(j = i + 1; j < 64; j++)
            {
                if((tempMat.M[j] & idM64[i]) == idM64[i])
                {
                    temp = tempMat.M[i];
                    tempMat.M[i] = tempMat.M[j];
                    tempMat.M[j] = temp;

                    flag = 0;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if(flag) //can not find 1 which means not invertible
            {
                invertible = 0;
                if (i < 63)
                {
                    p = i + 1 + cus_random()%(63 - i);//swap
                    temp = tempMat.M[p];
                    tempMat.M[p] = tempMat.M[i];
                    tempMat.M[i] = temp;
                    temp = (*Mat_inv).M[p];
                    (*Mat_inv).M[p] = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = temp;
                    trail[times][0] = 0;
                    trail[times][1] = p;
                    trail[times][2] = i;
                    times++;
                    for(t = i + 1; t < 64; t++)
                    {
                        if(cus_random()%2)
                        {
                            tempMat.M[t] ^= tempMat.M[i];
                            (*Mat_inv).M[t] ^= (*Mat_inv).M[i];
                            trail[times][0] = 1;
                            trail[times][1] = t;
                            trail[times][2] = i;
                            times++;
                        }
                    }
                }
            }
            else //can still contiune
            {
                for(k = i + 1; k < 64; k++)
                {
                    if((tempMat.M[k] & idM64[i]) == idM64[i])
                    {
                        tempMat.M[k] ^= tempMat.M[i];

                        (*Mat_inv).M[k] ^= (*Mat_inv).M[i];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    if(!invertible)//not invertible
    {
        for(t = 63; t >= 0; t--)
        {
            for(j = t - 1; j >= 0; j--)
            {
                if((tempMat.M[j] & idM64[t]) == idM64[t])
                {
                    tempMat.M[j] ^= tempMat.M[t];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[t];
                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }
        
        for(j = times - 1; j >= 0; j--)//generate inverse matrix
        {
            if(trail[j][0])//add
            {
                (*Mat).M[trail[j][1]] ^= (*Mat).M[trail[j][2]];
            }
            else//swap
            {
                temp = (*Mat).M[trail[j][1]];
                (*Mat).M[trail[j][1]] = (*Mat).M[trail[j][2]];
                (*Mat).M[trail[j][2]] = temp;
            }   
        }
    }
    else//invertible 
    {
        for(i = 63; i >= 0; i--)
        {
            for(j = i - 1; j >= 0; j--)
            {
                if((tempMat.M[j] & idM64[i]) == idM64[i])
                {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        copyM64(resultMat, Mat);
    }
}
void genMatpairM128(M128 *Mat, M128 *Mat_inv)//generate 128*128 invertible matrix and its inverse matrix
{
    int i, j, t, k;
    int p;
    M128 tempMat;
    M128 resultMat;
    uint64_t temp;
    uint8_t trail[16384][3];// generate trail
    int flag = 0;
    int times = 0;
    int invertible = 1;
    InitRandom((randseed) ^ matrixseed);
    identityM128(Mat);
    identityM128(Mat_inv);
    randM128(&tempMat);
    copyM128(tempMat, &resultMat); 
    for(i = 0; i < 64; i++)//diagonal = 1?
    {
        if((tempMat.M[i][0] & idM64[i]) == idM64[i])
        {
            for(j = i + 1; j < 128; j++)
            {
                if((tempMat.M[j][0] & idM64[i]) == idM64[i])
                {
                    tempMat.M[j][0] ^= tempMat.M[i][0];
                    tempMat.M[j][1] ^= tempMat.M[i][1];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        }
        else// swap to find 1
        {
            flag = 1;
            for(j = i + 1; j < 128; j++)
            {
                if((tempMat.M[j][0] & idM64[i]) == idM64[i])
                {
                    temp = tempMat.M[i][0];
                    tempMat.M[i][0] = tempMat.M[j][0];
                    tempMat.M[j][0] = temp;

                    temp = tempMat.M[i][1];
                    tempMat.M[i][1] = tempMat.M[j][1];
                    tempMat.M[j][1] = temp;

                    flag = 0;

                    temp = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = (*Mat_inv).M[j][0];
                    (*Mat_inv).M[j][0] = temp;

                    temp = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = (*Mat_inv).M[j][1];
                    (*Mat_inv).M[j][1] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if(flag) //can not find 1 which means not invertible
            {
                invertible = 0;
                p = i + 1 + cus_random()%(127 - i);//swap
                
                temp = tempMat.M[p][0];
                tempMat.M[p][0] = tempMat.M[i][0];
                tempMat.M[i][0] = temp;

                temp = tempMat.M[p][1];
                tempMat.M[p][1] = tempMat.M[i][1];
                tempMat.M[i][1] = temp;
                
                temp = (*Mat_inv).M[p][0];
                (*Mat_inv).M[p][0] = (*Mat_inv).M[i][0];
                (*Mat_inv).M[i][0] = temp;

                temp = (*Mat_inv).M[p][1];
                (*Mat_inv).M[p][1] = (*Mat_inv).M[i][1];
                (*Mat_inv).M[i][1] = temp;
                
                trail[times][0] = 0;
                trail[times][1] = p;
                trail[times][2] = i;
                times++;

                for(t = i + 1; t < 128; t++)
                {
                    if(cus_random()%2)
                    {
                        tempMat.M[t][0] ^= tempMat.M[i][0];
                        tempMat.M[t][1] ^= tempMat.M[i][1];

                        (*Mat_inv).M[t][0] ^= (*Mat_inv).M[i][0];
                        (*Mat_inv).M[t][1] ^= (*Mat_inv).M[i][1];
                        trail[times][0] = 1;
                        trail[times][1] = t;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
            else //can still contiune
            {
                for(k = i + 1; k < 128; k++)
                {
                    if((tempMat.M[k][0] & idM64[i]) == idM64[i])
                    {
                        tempMat.M[k][0] ^= tempMat.M[i][0];
                        tempMat.M[k][1] ^= tempMat.M[i][1];

                        (*Mat_inv).M[k][0] ^= (*Mat_inv).M[i][0];
                        (*Mat_inv).M[k][1] ^= (*Mat_inv).M[i][1];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    for(i = 64; i < 128; i++)//diagonal = 1?
    {
        if((tempMat.M[i][1] & idM64[i - 64]) == idM64[i - 64])
        {
            for(j = i + 1; j < 128; j++)
            {
                if((tempMat.M[j][1] & idM64[i - 64]) == idM64[i - 64])
                {
                    tempMat.M[j][1] ^= tempMat.M[i][1];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        }
        else// swap to find 1
        {
            flag = 1;
            for(j = i + 1; j < 128; j++)
            {
                if((tempMat.M[j][1] & idM64[i - 64]) == idM64[i - 64])
                {
                    temp = tempMat.M[i][1];
                    tempMat.M[i][1] = tempMat.M[j][1];
                    tempMat.M[j][1] = temp;

                    flag=0;

                    temp = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = (*Mat_inv).M[j][0];
                    (*Mat_inv).M[j][0] = temp;

                    temp = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = (*Mat_inv).M[j][1];
                    (*Mat_inv).M[j][1] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if(flag) //can not find 1 which means not invertible
            {
                invertible = 0;
                if(i < 127)
                {
                    p = i + 1 + cus_random()%(127 - i);//swap

                    temp = tempMat.M[p][1];
                    tempMat.M[p][1] = tempMat.M[i][1];
                    tempMat.M[i][1] = temp;
                    
                    temp = (*Mat_inv).M[p][0];
                    (*Mat_inv).M[p][0] = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = temp;

                    temp = (*Mat_inv).M[p][1];
                    (*Mat_inv).M[p][1] = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = temp;
                    
                    trail[times][0] = 0;
                    trail[times][1] = p;
                    trail[times][2] = i;
                    times++;

                    for(t = i + 1; t < 128; t++)
                    {
                        if(cus_random()%2)
                        {
                            tempMat.M[t][1] ^= tempMat.M[i][1];

                            (*Mat_inv).M[t][0] ^= (*Mat_inv).M[i][0];
                            (*Mat_inv).M[t][1] ^= (*Mat_inv).M[i][1];
                            trail[times][0] = 1;
                            trail[times][1] = t;
                            trail[times][2] = i;
                            times++;
                        }
                    }
                }
            }
            else //can still contiune
            {
                for(k = i + 1; k < 128; k++)
                {
                    if((tempMat.M[k][1] & idM64[i - 64]) == idM64[i - 64])
                    {
                        tempMat.M[k][1] ^= tempMat.M[i][1];

                        (*Mat_inv).M[k][0] ^= (*Mat_inv).M[i][0];
                        (*Mat_inv).M[k][1] ^= (*Mat_inv).M[i][1];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    if(!invertible)//not invertible
    {
        for(t = 127; t >= 64; t--)
        {
            for(j = t - 1; j >= 0; j--)
            {
                if((tempMat.M[j][1] & idM64[t - 64]) == idM64[t - 64])
                {
                    tempMat.M[j][1] ^= tempMat.M[t][1];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[t][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[t][1];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }
        for(t = 63; t >= 0; t--)
        {
            for(j = t - 1; j >= 0; j--)
            {
                if((tempMat.M[j][0] & idM64[t]) == idM64[t])
                {
                    tempMat.M[j][0] ^= tempMat.M[t][0];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[t][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[t][1];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }
        
        for(j = times - 1; j >= 0; j--)//generate inverse matrix
        {
            if(trail[j][0])//add
            {
                (*Mat).M[trail[j][1]][0] ^= (*Mat).M[trail[j][2]][0];
                (*Mat).M[trail[j][1]][1] ^= (*Mat).M[trail[j][2]][1];
            }
            else//swap
            {
                temp = (*Mat).M[trail[j][1]][0];
                (*Mat).M[trail[j][1]][0] = (*Mat).M[trail[j][2]][0];
                (*Mat).M[trail[j][2]][0] = temp;

                temp = (*Mat).M[trail[j][1]][1];
                (*Mat).M[trail[j][1]][1] = (*Mat).M[trail[j][2]][1];
                (*Mat).M[trail[j][2]][1] = temp;
            }   
        }
    }
    else//invertible 
    {
        for(i = 127; i >= 64; i--)
        {
            for(j = i - 1; j >= 0; j--)
            {
                if((tempMat.M[j][1] & idM64[i - 64]) == idM64[i - 64])
                {
                    tempMat.M[j][1] ^= tempMat.M[i][1];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                }
            }
        }
        for(i = 63; i >= 0; i--)
        {
            for(j = i - 1; j >= 0; j--)
            {
                if((tempMat.M[j][0] & idM64[i]) == idM64[i])
                {
                    tempMat.M[j][0] ^= tempMat.M[i][0];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                }
            }
        }
        copyM128(resultMat, Mat);
    }
}
void genaffinepairM4(Aff4 *aff, Aff4 *aff_inv)//generate a pair of affine
{
    genMatpairM4(&(aff->Mat), &(aff_inv->Mat));
    randV4(&(aff->Vec));
    MatMulVecM4((*aff_inv).Mat, (*aff).Vec, &(aff_inv->Vec));
}
void genaffinepairM8(Aff8 *aff, Aff8 *aff_inv)//generate a pair of affine
{
    genMatpairM8(&(aff->Mat), &(aff_inv->Mat));
    randV8(&(aff->Vec));
    MatMulVecM8((*aff_inv).Mat, (*aff).Vec, &(aff_inv->Vec));
}
void genaffinepairM16(Aff16 *aff, Aff16 *aff_inv)//generate a pair of affine
{
    genMatpairM16(&(aff->Mat), &(aff_inv->Mat));
    randV16(&(aff->Vec));
    MatMulVecM16((*aff_inv).Mat, (*aff).Vec, &(aff_inv->Vec));
}
void genaffinepairM32(Aff32 *aff, Aff32 *aff_inv)//generate a pair of affine
{
    genMatpairM32(&(aff->Mat), &(aff_inv->Mat));
    randV32(&(aff->Vec));
    MatMulVecM32((*aff_inv).Mat, (*aff).Vec, &(aff_inv->Vec));
}
void genaffinepairM64(Aff64 *aff, Aff64 *aff_inv)//generate a pair of affine
{
    genMatpairM64(&(aff->Mat), &(aff_inv->Mat));
    randV64(&(aff->Vec));
    MatMulVecM64((*aff_inv).Mat, (*aff).Vec, &(aff_inv->Vec));
}
void genaffinepairM128(Aff128 *aff, Aff128 *aff_inv)//generate a pair of affine
{
    genMatpairM128(&(aff->Mat), &(aff_inv->Mat));
    randV128(&(aff->Vec));
    MatMulVecM128((*aff_inv).Mat, (*aff).Vec, &(aff_inv->Vec));
}
void MatrixcomM8to32(M8 m1, M8 m2, M8 m3, M8 m4, M32 *mat)//diagonal matrix concatenation, four 8*8 -> 32*32
{
    int i;
    int j = 0;
    uint8_t* m;
    initM32(mat);
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j];
        *(m+3) = m1.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j];
        *(m+2) = m2.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j];
        *(m+1) = m3.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j];
        *m = m4.M[i];
        j++;
    }
}
void VectorcomV8to32(V8 v1, V8 v2, V8 v3, V8 v4, V32 *vec)//4 vectors concatenation
{
    uint8_t* v;
    v = (uint8_t*)&(*vec).V;
    *(v+3) = v1.V;
    *(v+2) = v2.V;
    *(v+1) = v3.V;
    *v = v4.V;
}
void affinecomM8to32(Aff8 aff1, Aff8 aff2, Aff8 aff3, Aff8 aff4, Aff32 *aff)//diagonal affine concatenation, four 8*8 -> 32*32
{
    MatrixcomM8to32(aff1.Mat, aff2.Mat, aff3.Mat, aff4.Mat, &(aff->Mat));
    VectorcomV8to32(aff1.Vec, aff2.Vec, aff3.Vec, aff4.Vec, &(aff->Vec));
}
void MatrixcomM16to64(M16 m1, M16 m2, M16 m3, M16 m4, M64 *mat)//diagonal matrix concatenation, four 16*16 -> 64*64
{
    int i;
    int j = 0;
    uint16_t* m;
    initM64(mat);
    for(i = 0; i < 16; i++)
    {
        m = (uint16_t*)&(*mat).M[j];
        *(m+3) = m1.M[i];
        j++;
    }
    for(i = 0; i < 16; i++)
    {
        m = (uint16_t*)&(*mat).M[j];
        *(m+2) = m2.M[i];
        j++;
    }
    for(i = 0; i < 16; i++)
    {
        m = (uint16_t*)&(*mat).M[j];
        *(m+1) = m3.M[i];
        j++;
    }
    for(i = 0; i < 16; i++)
    {
        m = (uint16_t*)&(*mat).M[j];
        *m = m4.M[i];
        j++;
    }
}
void VectorcomV16to64(V16 v1, V16 v2, V16 v3, V16 v4, V64 *vec)//4 vectors concatenation
{
    uint16_t* v;
    v = (uint16_t*)&(*vec).V;
    *(v+3) = v1.V;
    *(v+2) = v2.V;
    *(v+1) = v3.V;
    *v = v4.V;
}
void affinecomM16to64(Aff16 aff1, Aff16 aff2, Aff16 aff3, Aff16 aff4, Aff64 *aff)//diagonal affine concatenation,four 16*16 -> 64*64
{
    MatrixcomM16to64(aff1.Mat, aff2.Mat, aff3.Mat, aff4.Mat, &(aff->Mat));
    VectorcomV16to64(aff1.Vec, aff2.Vec, aff3.Vec, aff4.Vec, &(aff->Vec));
}
void MatrixcomM8to64(M8 m1, M8 m2, M8 m3, M8 m4, M8 m5, M8 m6, M8 m7, M8 m8, M64 *mat)//diagonal matrix concatenation,four 8*8 -> 64*64
{
    int i;
    int j = 0;
    uint8_t* m;
    initM64(mat);
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j];
        *(m+7) = m1.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j];
        *(m+6) = m2.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j];
        *(m+5) = m3.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j];
        *(m+4) = m4.M[i];
        j++;
    }
    for(i=0;i<8;i++)
    {
        m = (uint8_t*)&(*mat).M[j];
        *(m+3) = m5.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j];
        *(m+2) = m6.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j];
        *(m+1) = m7.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j];
        *m = m8.M[i];
        j++;
    }
}
void VectorcomV8to64(V8 v1, V8 v2, V8 v3, V8 v4, V8 v5, V8 v6, V8 v7, V8 v8, V64 *vec)//8 vectors concatenation
{
    uint8_t* v;
    v = (uint8_t*)&(*vec).V;
    *(v+7) = v1.V;
    *(v+6) = v2.V;
    *(v+5) = v3.V;
    *(v+4) = v4.V;
    *(v+3) = v5.V;
    *(v+2) = v6.V;
    *(v+1) = v7.V;
    *v = v8.V;
}
void affinecomM8to64(Aff8 aff1, Aff8 aff2, Aff8 aff3, Aff8 aff4, Aff8 aff5, Aff8 aff6, Aff8 aff7, Aff8 aff8, Aff64 *aff)//diagonal affine concatenation, four 8*8 -> 64*64
{
    MatrixcomM8to64(aff1.Mat, aff2.Mat, aff3.Mat, aff4.Mat, aff5.Mat, aff6.Mat, aff7.Mat, aff8.Mat, &(aff->Mat));
    VectorcomV8to64(aff1.Vec, aff2.Vec, aff3.Vec, aff4.Vec, aff5.Vec, aff6.Vec, aff7.Vec, aff8.Vec, &(aff->Vec));
}
void MatrixcomM32to128(M32 m1, M32 m2, M32 m3, M32 m4, M128 *mat)//diagonal matrix concatenation, four 32*32 -> 128*128
{
    int i;
    int j = 0;
    uint32_t* m;
    initM128(mat);
    for(i = 0; i < 32; i++)
    {
        m = (uint32_t*)&(*mat).M[j][0];
        *(m+1) = m1.M[i];
        j++;
    }
    for(i = 0; i < 32; i++)
    {
        m = (uint32_t*)&(*mat).M[j][0];
        *m = m2.M[i];
        j++;
    }
    for(i = 0; i < 32; i++)
    {
        m = (uint32_t*)&(*mat).M[j][1];
        *(m+1) = m3.M[i];
        j++;
    }
    for(i = 0; i < 32; i++)
    {
        m = (uint32_t*)&(*mat).M[j][1];
        *m = m4.M[i];
        j++;
    }
}
void VectorcomV32to128(V32 v1, V32 v2, V32 v3, V32 v4, V128 *vec)//4 vectors concatenation
{
    uint32_t* v;
    v = (uint32_t*)&(*vec).V[0];
    *(v+1) = v1.V;
    *v = v2.V;
    v = (uint32_t*)&(*vec).V[1];
    *(v+1) = v3.V;
    *v = v4.V;
}
void affinecomM32to128(Aff32 aff1, Aff32 aff2, Aff32 aff3, Aff32 aff4, Aff128 *aff)//diagonal affine concatenation, four 32*32 -> 128*128
{
    MatrixcomM32to128(aff1.Mat, aff2.Mat, aff3.Mat, aff4.Mat, &(aff->Mat));
    VectorcomV32to128(aff1.Vec, aff2.Vec, aff3.Vec, aff4.Vec, &(aff->Vec));
}
void MatrixcomM8to128(M8 m1, M8 m2, M8 m3, M8 m4, M8 m5, M8 m6, M8 m7, M8 m8, M8 m9, M8 m10, M8 m11, M8 m12, M8 m13, M8 m14, M8 m15, M8 m16, M128 *mat)//diagonal matrix concatenation, 16 8*8 -> 128*128
{
    int i;
    int j = 0;
    uint8_t* m;
    initM128(mat);
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j][0];
        *(m+7) = m1.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j][0];
        *(m+6) = m2.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j][0];
        *(m+5) = m3.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j][0];
        *(m+4) = m4.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j][0];
        *(m+3) = m5.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j][0];
        *(m+2) = m6.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j][0];
        *(m+1) = m7.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j][0];
        *m = m8.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j][1];
        *(m+7) = m9.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j][1];
        *(m+6) = m10.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j][1];
        *(m+5) = m11.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j][1];
        *(m+4) = m12.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j][1];
        *(m+3) = m13.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j][1];
        *(m+2) = m14.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j][1];
        *(m+1) = m15.M[i];
        j++;
    }
    for(i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j][1];
        *m = m16.M[i];
        j++;
    }
}
void VectorcomV8to128(V8 v1, V8 v2, V8 v3, V8 v4, V8 v5, V8 v6, V8 v7, V8 v8, V8 v9, V8 v10, V8 v11, V8 v12, V8 v13, V8 v14, V8 v15, V8 v16, V128 *vec)//16 vectors concatenation
{
    uint8_t* v;
    v = (uint8_t*)&(*vec).V[0];
    *(v+7) = v1.V;
    *(v+6) = v2.V;
    *(v+5) = v3.V;
    *(v+4) = v4.V;
    *(v+3) = v5.V;
    *(v+2) = v6.V;
    *(v+1) = v7.V;
    *v = v8.V;
    v = (uint8_t*)&(*vec).V[1];
    *(v+7) = v9.V;
    *(v+6) = v10.V;
    *(v+5) = v11.V;
    *(v+4) = v12.V;
    *(v+3) = v13.V;
    *(v+2) = v14.V;
    *(v+1) = v15.V;
    *v = v16.V;
}
void affinecomM8to128(Aff8 aff1, Aff8 aff2, Aff8 aff3, Aff8 aff4, Aff8 aff5, Aff8 aff6, Aff8 aff7, Aff8 aff8, Aff8 aff9, Aff8 aff10, Aff8 aff11, Aff8 aff12, Aff8 aff13, Aff8 aff14, Aff8 aff15, Aff8 aff16, Aff128 *aff)//diagonal affine concatenation, 16 8*8 -> 128*128
{
    MatrixcomM8to128(aff1.Mat, aff2.Mat, aff3.Mat, aff4.Mat, aff5.Mat, aff6.Mat, aff7.Mat, aff8.Mat, aff9.Mat, aff10.Mat, aff11.Mat, aff12.Mat, aff13.Mat, aff14.Mat, aff15.Mat, aff16.Mat, &(aff->Mat));
    VectorcomV8to128(aff1.Vec, aff2.Vec, aff3.Vec, aff4.Vec, aff5.Vec, aff6.Vec, aff7.Vec, aff8.Vec, aff9.Vec, aff10.Vec, aff11.Vec, aff12.Vec, aff13.Vec, aff14.Vec, aff15.Vec, aff16.Vec, &(aff->Vec));
}
void MatrixcomM16to128(M16 m1, M16 m2, M16 m3, M16 m4, M16 m5, M16 m6, M16 m7, M16 m8, M128 *mat)//diagonal matrix concatenation, 8 16*16 -> 128*128
{
    int i;
    int j = 0;
    uint16_t* m;
    initM128(mat);
    for(i = 0; i < 16; i++)
    {
        m = (uint16_t*)&(*mat).M[j][0];
        *(m+3) = m1.M[i];
        j++;
    }
    for(i = 0; i < 16; i++)
    {
        m = (uint16_t*)&(*mat).M[j][0];
        *(m+2) = m2.M[i];
        j++;
    }
    for(i = 0; i < 16; i++)
    {
        m = (uint16_t*)&(*mat).M[j][0];
        *(m+1) = m3.M[i];
        j++;
    }
    for(i = 0; i < 16; i++)
    {
        m = (uint16_t*)&(*mat).M[j][0];
        *m = m4.M[i];
        j++;
    }
    for(i = 0; i < 16; i++)
    {
        m = (uint16_t*)&(*mat).M[j][1];
        *(m+3) = m5.M[i];
        j++;
    }
    for(i = 0; i < 16; i++)
    {
        m = (uint16_t*)&(*mat).M[j][1];
        *(m+2) = m6.M[i];
        j++;
    }
    for(i = 0; i < 16; i++)
    {
        m = (uint16_t*)&(*mat).M[j][1];
        *(m+1) = m7.M[i];
        j++;
    }
    for(i = 0; i < 16; i++)
    {
        m = (uint16_t*)&(*mat).M[j][1];
        *m = m8.M[i];
        j++;
    }
}
void VectorcomV16to128(V16 v1, V16 v2, V16 v3, V16 v4, V16 v5, V16 v6, V16 v7, V16 v8, V128 *vec)//8 vectors concatenation
{
    uint16_t* v;
    v = (uint16_t*)&(*vec).V[0];
    *(v+3) = v1.V;
    *(v+2) = v2.V;
    *(v+1) = v3.V;
    *v = v4.V;
    v = (uint16_t*)&(*vec).V[1];
    *(v+3) = v5.V;
    *(v+2) = v6.V;
    *(v+1) = v7.V;
    *v = v8.V;
}
void affinecomM16to128(Aff16 aff1, Aff16 aff2, Aff16 aff3, Aff16 aff4, Aff16 aff5, Aff16 aff6, Aff16 aff7, Aff16 aff8, Aff128 *aff)//diagonal affine concatenation, 8 16*16 -> 128*128
{
    MatrixcomM16to128(aff1.Mat, aff2.Mat, aff3.Mat, aff4.Mat, aff5.Mat, aff6.Mat, aff7.Mat, aff8.Mat, &(aff->Mat));
    VectorcomV16to128(aff1.Vec, aff2.Vec, aff3.Vec, aff4.Vec, aff5.Vec, aff6.Vec, aff7.Vec, aff8.Vec, &(aff->Vec));
}
void MattransM4(M4 Mat, M4 *Mat_trans)//matrix tansposition M4
{
    int i, j;
    initM4(Mat_trans);
    for(i = 0; i < 4; i++)
    {
        for(j = 0; j < 4; j++)
        {
            if(Mat.M[i] & idM4[j]) (*Mat_trans).M[j] ^= idM4[i];
        }
    }
}
void MattransM8(M8 Mat, M8 *Mat_trans)//matrix tansposition M8
{
    int i, j;
    initM8(Mat_trans);
    for(i = 0; i < 8; i++)
    {
        for(j = 0; j < 8; j++)
        {
            if(Mat.M[i] & idM8[j]) (*Mat_trans).M[j] ^= idM8[i];
        }
    }
}
void MattransM16(M16 Mat, M16 *Mat_trans)//matrix tansposition M16
{
    int i, j;
    initM16(Mat_trans);
    for(i = 0; i < 16; i++)
    {
        for(j = 0; j < 16; j++)
        {
            if(Mat.M[i] & idM16[j]) (*Mat_trans).M[j] ^= idM16[i];
        }
    }
}
void MattransM32(M32 Mat, M32 *Mat_trans)//matrix tansposition M32
{
    int i, j;
    initM32(Mat_trans);
    for(i = 0; i < 32; i++)
    {
        for(j = 0; j < 32; j++)
        {
            if(Mat.M[i] & idM32[j]) (*Mat_trans).M[j] ^= idM32[i];
        }
    }
}
void MattransM64(M64 Mat, M64 *Mat_trans)//matrix tansposition M64
{
    int i, j;
    initM64(Mat_trans);
    for(i = 0; i < 64; i++)
    {
        for(j = 0; j < 64; j++)
        {
            if(Mat.M[i] & idM64[j]) (*Mat_trans).M[j] ^= idM64[i];
        }
    }
}
void MattransM128(M128 Mat, M128 *Mat_trans)//matrix tansposition M128
{
    int i, j;
    initM128(Mat_trans);
    for(i = 0; i < 64; i++)
    {
        for(j = 0; j < 64; j++)
        {
            if(Mat.M[i][0] & idM64[j]) (*Mat_trans).M[j][0] ^= idM64[i];
            if(Mat.M[i][1] & idM64[j]) (*Mat_trans).M[j+64][0] ^= idM64[i];
        }
    }
    for(i = 64; i < 128; i++)
    {
        for(j = 0; j < 64; j++)
        {
            if(Mat.M[i][0] & idM64[j]) (*Mat_trans).M[j][1] ^= idM64[i-64];
            if(Mat.M[i][1] & idM64[j]) (*Mat_trans).M[j+64][1] ^= idM64[i-64];
        }
    }
}
void MatAddMatM4(M4 Mat1, M4 Mat2, M4 *Mat)
{
    int i;
    for(i = 0; i < 4; i++)
    {
        (*Mat).M[i] = Mat1.M[i] ^ Mat2.M[i];
    }
}
void MatAddMatM8(M8 Mat1, M8 Mat2, M8 *Mat)
{
    int i;
    for(i = 0; i < 8; i++)
    {
        (*Mat).M[i] = Mat1.M[i] ^ Mat2.M[i];
    }
}
void MatAddMatM16(M16 Mat1, M16 Mat2, M16 *Mat)
{
    int i;
    for(i = 0; i < 16; i++)
    {
        (*Mat).M[i] = Mat1.M[i] ^ Mat2.M[i];
    }
}
void MatAddMatM32(M32 Mat1, M32 Mat2, M32 *Mat)
{
    int i;
    for(i = 0; i < 32; i++)
    {
        (*Mat).M[i] = Mat1.M[i] ^ Mat2.M[i];
    }
}
void MatAddMatM64(M64 Mat1, M64 Mat2, M64 *Mat)
{
    int i;
    for(i = 0; i < 64; i++)
    {
        (*Mat).M[i] = Mat1.M[i] ^ Mat2.M[i];
    }
}
void MatAddMatM128(M128 Mat1, M128 Mat2, M128 *Mat)
{
    int i;
    for(i = 0; i < 128; i++)
    {
        (*Mat).M[i][0] = Mat1.M[i][0] ^ Mat2.M[i][0];
        (*Mat).M[i][1] = Mat1.M[i][1] ^ Mat2.M[i][1];
    }
}
void MatMulMatM4(M4 Mat1, M4 Mat2, M4 *Mat)//matrix multiplication 4*4 mul 4*4 -> 4*4
{
    int i, j;
    M4 Mat2_trans;
    initM4(Mat);
    MattransM4(Mat2, &Mat2_trans);
    for(i = 0; i < 4; i++)
    {
        for(j = 0; j < 4; j++)
        {
            if(xorU4(Mat1.M[i] & Mat2_trans.M[j] & 0x0f)) (*Mat).M[i] ^= idM4[j];
        }       
    }
}
void MatMulMatM8(M8 Mat1, M8 Mat2, M8 *Mat)//matrix multiplication 8*8 mul 8*8 -> 8*8
{
    int i, j;
    M8 Mat2_trans;
    initM8(Mat);
    MattransM8(Mat2, &Mat2_trans);
    for(i = 0; i < 8; i++)
    {
        for(j = 0; j < 8; j++)
        {
            if(xorU8(Mat1.M[i] & Mat2_trans.M[j])) (*Mat).M[i] ^= idM8[j];
        }       
    }
}
void MatMulMatM16(M16 Mat1, M16 Mat2, M16 *Mat)//matrix multiplication 16*16 mul 16*16 -> 16*16
{
    int i, j;
    M16 Mat2_trans;
    initM16(Mat);
    MattransM16(Mat2, &Mat2_trans);
    for(i = 0; i < 16; i++)
    {
        for(j = 0; j < 16; j++)
        {
            if(xorU16(Mat1.M[i] & Mat2_trans.M[j])) (*Mat).M[i] ^= idM16[j];
        }       
    }
}
void MatMulMatM32(M32 Mat1, M32 Mat2, M32 *Mat)//matrix multiplication 32*32 mul 32*32 -> 32*32
{
    int i, j;
    M32 Mat2_trans;
    initM32(Mat);
    MattransM32(Mat2, &Mat2_trans);
    for(i = 0; i < 32; i++)
    {
        for(j = 0; j < 32; j++)
        {
            if(xorU32(Mat1.M[i] & Mat2_trans.M[j])) (*Mat).M[i] ^= idM32[j];
        }       
    } 
}
void MatMulMatM64(M64 Mat1, M64 Mat2, M64 *Mat)//matrix multiplication 64*64 mul 64*64 -> 64*64
{
    int i, j;
    M64 Mat2_trans;
    initM64(Mat);
    MattransM64(Mat2, &Mat2_trans);
    for(i = 0; i < 64; i++)
    {
        for(j = 0; j < 64; j++)
        {
            if(xorU64(Mat1.M[i] & Mat2_trans.M[j])) (*Mat).M[i] ^= idM64[j];
        }       
    } 
}
void MatMulMatM128(M128 Mat1, M128 Mat2, M128 *Mat)//matrix multiplication 128*128 mul 128*128 -> 128*128
{
    int i, j;
    M128 Mat2_trans;
    uint64_t temp[2];
    initM128(Mat);
    MattransM128(Mat2, &Mat2_trans);
    for(i = 0; i < 128; i++)
    {
        for(j = 0; j < 64; j++)
        {
            temp[0] = Mat1.M[i][0] & Mat2_trans.M[j][0];
            temp[1] = Mat1.M[i][1] & Mat2_trans.M[j][1];
            if(xorU128(temp)) (*Mat).M[i][0] ^= idM64[j];
        }
        for(j = 64; j < 128; j++)
        {
            temp[0] = Mat1.M[i][0] & Mat2_trans.M[j][0];
            temp[1] = Mat1.M[i][1] & Mat2_trans.M[j][1];
            if(xorU128(temp)) (*Mat).M[i][1] ^= idM64[j-64];
        }
    } 
}
void affinemixM4(Aff4 aff, Aff4 preaff_inv, Aff4 *mixaff)//mixed transformation of (previous affine inversion) and this round affine
{
    MatMulMatM4(aff.Mat, preaff_inv.Mat, &(mixaff->Mat));
    MatMulVecM4(aff.Mat, preaff_inv.Vec, &(mixaff->Vec));
    (*mixaff).Vec.V ^= aff.Vec.V;
}
void affinemixM8(Aff8 aff, Aff8 preaff_inv, Aff8 *mixaff)//mixed transformation of (previous affine inversion) and this round affine
{
    MatMulMatM8(aff.Mat, preaff_inv.Mat, &(mixaff->Mat));
    MatMulVecM8(aff.Mat, preaff_inv.Vec, &(mixaff->Vec));
    (*mixaff).Vec.V ^= aff.Vec.V;
}
void affinemixM16(Aff16 aff, Aff16 preaff_inv, Aff16 *mixaff)//mixed transformation of (previous affine inversion) and this round affine
{
    MatMulMatM16(aff.Mat, preaff_inv.Mat, &(mixaff->Mat));
    MatMulVecM16(aff.Mat, preaff_inv.Vec, &(mixaff->Vec));
    (*mixaff).Vec.V ^= aff.Vec.V;
}
void affinemixM32(Aff32 aff, Aff32 preaff_inv, Aff32 *mixaff)//mixed transformation of (previous affine inversion) and this round affine
{
    MatMulMatM32(aff.Mat, preaff_inv.Mat, &(mixaff->Mat));
    MatMulVecM32(aff.Mat, preaff_inv.Vec, &(mixaff->Vec));
    (*mixaff).Vec.V ^= aff.Vec.V;
}
void affinemixM64(Aff64 aff, Aff64 preaff_inv, Aff64 *mixaff)//mixed transformation of (previous affine inversion) and this round affine
{
    MatMulMatM64(aff.Mat, preaff_inv.Mat, &(mixaff->Mat));
    MatMulVecM64(aff.Mat, preaff_inv.Vec, &(mixaff->Vec));
    (*mixaff).Vec.V ^= aff.Vec.V;
}
void affinemixM128(Aff128 aff, Aff128 preaff_inv, Aff128 *mixaff)//mixed transformation of (previous affine inversion) and this round affine
{
    MatMulMatM128(aff.Mat, preaff_inv.Mat, &(mixaff->Mat));
    MatMulVecM128(aff.Mat, preaff_inv.Vec, &(mixaff->Vec));
    (*mixaff).Vec.V[0] ^= aff.Vec.V[0];
    (*mixaff).Vec.V[1] ^= aff.Vec.V[1];
}

unsigned int m_index;
unsigned int m_intermediateOffset;
unsigned int permuteQPR(unsigned int x)
{
    static const unsigned int prime = 4294967291u;
    if (x >= prime)
        return x;
    unsigned int residue = ((unsigned long long) x * x) % prime;
    return (x <= prime / 2) ? residue : prime - residue;
}

void InitRandom(unsigned int seedBase)
{
    unsigned int seedOffset = seedBase+1;
    m_index = permuteQPR(permuteQPR(seedBase) + 0x682f0162);
    m_intermediateOffset = permuteQPR(permuteQPR(seedOffset) + 0x46790903);
}

unsigned int cus_random(void)
{
    return permuteQPR((permuteQPR(m_index++) + m_intermediateOffset) ^ 0x5bf03636);
}

void generatePermutation(u8 *permutation, u8 *inverse)
{
	int i, j;
	u8 temp;
	for (i = 0; i < 16; i++)
	{
		permutation[i] = i;
	}
	for (i = 0; i < 15; i++)
	{
		j = cus_random()%(16 - i);
		temp = permutation[i];
		permutation[i] = permutation[i+j];
		permutation[i + j] = temp;
	}
	for (i = 0; i < 16; i++)
	{
		inverse[permutation[i]] = i;
	}
}

u8 gMul (u8 a, u8 b) 
{
  int i;
  u8 p = 0;
  u8 hi_bit_set;

  for (i = 0; i < 8; i++) {
    if ((b & 1) == 1)
      p ^= a;
    hi_bit_set = (a & 0x80);
    a <<= 1;
    if (hi_bit_set == 0x80)
      a ^= 0x1b;
    b >>= 1;
  }
return p;
}

void shiftRows (u8 state[16]) 
{
  int i;
  u8 out[16];
  int shiftTab[16] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
  for (i = 0; i < 16; i++) 
  {
    out[i] = state[shiftTab[i]];
  }
  memcpy(state, out, sizeof(out));
}

void vs_key_generator(uint8_t key[16], uint32_t seed1, uint32_t seed2)
{
    int i, j, x, y, k;
    u8 expandedKey[176] = {0};
    
    M8 L[9][16];
    M8 L_inv[9][16];
    M32 MB[9][4]={0};
    M32 MB_inv[9][4];
    M8 ex_in[16];
    M8 ex_in_inv[16];
    M8 ex_out[16];
    M8 ex_out_inv[16];

	SetRandSeed(seed1, seed2);

    for(i = 0; i < 9; i++)
    {
        for(j = 0; j < 16; j++)
        {
            genMatpairM8(&L[i][j], &L_inv[i][j]);
        }
    }
    for(i = 0; i < 9; i++)
    {
        for(j = 0; j < 4; j++)
        {
            genMatpairM32(&MB[i][j], &MB_inv[i][j]);
        }
    }
    for(i = 0; i < 16; i++)
    {
        genMatpairM8(&ex_in[i], &ex_in_inv[i]);
        genMatpairM8(&ex_out[i], &ex_out_inv[i]);
    }

    u32 Tyi[4][256];
    for (x = 0; x < 256; x++)
    {
        Tyi[0][x] = (gMul(2, x) << 24) | (x << 16) | (x << 8) | gMul(3, x);
        Tyi[1][x] = (gMul(3, x) << 24) | (gMul(2, x) << 16) | (x << 8) | x;
        Tyi[2][x] = (x << 24) | (gMul(3, x) << 16) | (gMul(2, x) << 8) | x;
        Tyi[3][x] = (x << 24) | (x << 16) | (gMul(3, x) << 8) | gMul(2, x);
    }

    M32 Out_L[9][4];
    for(i = 0; i < 9; i++)
    {
        for(j = 0; j < 4; j++)
        {
            MatrixcomM8to32(L[i][4 * j], L[i][4 * j + 1], L[i][4 * j + 2], L[i][4 * j + 3], &Out_L[i][j]);
        }
    }

    u8 TypeII_out[9][16][8][16];
    u8 TypeII_out_inv[9][16][8][16];
    u8 TypeIV_II_out1[9][8][8][16];
    u8 TypeIV_II_out1_inv[9][8][8][16];
    u8 TypeIV_II_out2[9][4][8][16];
    u8 TypeIV_II_out2_inv[9][4][8][16];

    u8 TypeIII_out[9][16][8][16];
    u8 TypeIII_out_inv[9][16][8][16];
    u8 TypeIV_III_out1[9][8][8][16];
    u8 TypeIV_III_out1_inv[9][8][8][16];
    u8 TypeIV_III_out2[9][4][8][16];
    u8 TypeIV_III_out2_inv[9][4][8][16];

    u8 TypeII_ex_in[16][2][16];
    u8 TypeII_ex_in_inv[16][2][16];
    u8 TypeIII_ex_out[16][2][16];
    u8 TypeIII_ex_out_inv[16][2][16];

    //InitRandom((unsigned int)time(NULL));
    InitRandom(0x193f203a);
    for(i = 0; i < 9; i++)
    {
        for(j = 0; j < 16; j++)
        {
            for(k = 0; k < 8; k++)
            {
                u8 permutation[16];
                u8 inverse[16];
                generatePermutation(permutation, inverse);
                for(x = 0; x < 16; x++)
                {
                    TypeII_out[i][j][k][x] = permutation[x];
                    TypeII_out_inv[i][j][k][x] = inverse[x];
                }
                generatePermutation(permutation, inverse);
                for(x = 0; x < 16; x++)
                {
                    TypeIII_out[i][j][k][x] = permutation[x];
                    TypeIII_out_inv[i][j][k][x] = inverse[x];
                }
            }
        }
    }
    for(i = 0; i < 9; i++)
    {
        for(j = 0; j < 8; j++)
        {
            for(k = 0; k < 8; k++)
            {
                u8 permutation[16];
                u8 inverse[16];
                generatePermutation(permutation, inverse);
                for(x = 0; x < 16; x++)
                {
                    TypeIV_II_out1[i][j][k][x] = permutation[x];
                    TypeIV_II_out1_inv[i][j][k][x] = inverse[x];
                }
                generatePermutation(permutation, inverse);
                for(x = 0; x < 16; x++)
                {
                    TypeIV_III_out1[i][j][k][x] = permutation[x];
                    TypeIV_III_out1_inv[i][j][k][x] = inverse[x];
                }
            }
        }
    }
    for(i = 0; i < 9; i++)
    {
        for(j = 0; j < 4; j++)
        {
            for(k = 0; k < 8; k++)
            {
                u8 permutation[16];
                u8 inverse[16];
                generatePermutation(permutation, inverse);
                for(x = 0; x < 16; x++)
                {
                    TypeIV_II_out2[i][j][k][x] = permutation[x];
                    TypeIV_II_out2_inv[i][j][k][x] = inverse[x];
                }
                generatePermutation(permutation, inverse);
                for(x = 0; x < 16; x++)
                {
                    TypeIV_III_out2[i][j][k][x] = permutation[x];
                    TypeIV_III_out2_inv[i][j][k][x] = inverse[x];
                }
            }
        }
    }

    for(i = 0; i < 16; i++)
    {
        for(j = 0; j < 2; j++)
        {
            u8 permutation[16];
            u8 inverse[16];
            generatePermutation(permutation, inverse);
            for(x = 0; x < 16; x++)
            {
                TypeII_ex_in[i][j][x] = permutation[x];
                TypeII_ex_in_inv[i][j][x] = inverse[x];
            }
            generatePermutation(permutation, inverse);
            for(x = 0; x < 16; x++)
            {
                TypeIII_ex_out[i][j][x] = permutation[x];
                TypeIII_ex_out_inv[i][j][x] = inverse[x];
            }
        }
    }
    
    int columnindex[]={0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3};
    int shiftindex[]={0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
    //Round 1
    shiftRows (expandedKey + 16 * 0);
    for(j = 0; j < 16; j++)//type_II
    {
        u8 temp_u8;
        u32 temp_u32;
        for(x = 0; x < 256; x++)
        {
            temp_u8 = (TypeII_ex_in_inv[shiftindex[j]][0][(x & 0xf0) >> 4] << 4) | (TypeII_ex_in_inv[shiftindex[j]][1][(x & 0x0f)]);
            temp_u8 = MatMulNumM8(ex_in_inv[shiftindex[j]], temp_u8);
            temp_u8 = SBox[temp_u8 ^ expandedKey[16 * 0 + j]];
            temp_u32 = Tyi[j % 4][temp_u8];
            temp_u32 = MatMulNumM32(MB[0][columnindex[j]], temp_u32);
            TypeII[0][j][x] = (TypeII_out[0][j][0][(temp_u32 & 0xf0000000) >> 28] << 28) | (TypeII_out[0][j][1][(temp_u32 & 0x0f000000) >> 24] << 24) | (TypeII_out[0][j][2][(temp_u32 & 0x00f00000) >> 20] << 20) | (TypeII_out[0][j][3][(temp_u32 & 0x000f0000) >> 16] << 16) | (TypeII_out[0][j][4][(temp_u32 & 0x0000f000) >> 12] << 12) | (TypeII_out[0][j][5][(temp_u32 & 0x00000f00) >> 8] << 8) | (TypeII_out[0][j][6][(temp_u32 & 0x000000f0) >> 4] << 4) | (TypeII_out[0][j][7][(temp_u32 & 0x0000000f)]);
        }
    }
    for(j = 0; j < 16; j++)//type_III
    {
        u8 temp_u8;
        u32 temp_u32;
        int shiftbit[]={24, 16, 8, 0};
        for(x = 0; x < 256; x++)
        {
            temp_u8 = (TypeIV_II_out2_inv[0][columnindex[j]][(j % 4) * 2][(x & 0xf0) >> 4] << 4) | (TypeIV_II_out2_inv[0][columnindex[j]][(j % 4) * 2 + 1][(x & 0x0f)]); 
            temp_u32 = temp_u8 << shiftbit[j % 4];
            temp_u32 = MatMulNumM32(MB_inv[0][columnindex[j]], temp_u32);
            temp_u32 = MatMulNumM32(Out_L[0][columnindex[j]], temp_u32);
            TypeIII[0][j][x] = (TypeIII_out[0][j][0][(temp_u32 & 0xf0000000) >> 28] << 28) | (TypeIII_out[0][j][1][(temp_u32 & 0x0f000000) >> 24] << 24) | (TypeIII_out[0][j][2][(temp_u32 & 0x00f00000) >> 20] << 20) | (TypeIII_out[0][j][3][(temp_u32 & 0x000f0000) >> 16] << 16) | (TypeIII_out[0][j][4][(temp_u32 & 0x0000f000) >> 12] << 12) | (TypeIII_out[0][j][5][(temp_u32 & 0x00000f00) >> 8] << 8) | (TypeIII_out[0][j][6][(temp_u32 & 0x000000f0) >> 4] << 4) | (TypeIII_out[0][j][7][(temp_u32 & 0x0000000f)]);
        }
    }

    //Round 2-9
    for (i = 1; i < 9; i++)//Type_II
    {
        shiftRows (expandedKey + 16 * i);
        for(j = 0; j < 16; j++)
        {
            u8 temp_u8;
            u32 temp_u32;
            for(x = 0; x < 256; x++)
            {
                temp_u8 = (TypeIV_III_out2_inv[i - 1][columnindex[shiftindex[j]]][(shiftindex[j] % 4) * 2][(x & 0xf0) >> 4] << 4) | (TypeIV_III_out2_inv[i - 1][columnindex[shiftindex[j]]][(shiftindex[j] % 4) * 2 + 1][(x & 0x0f)]);
                temp_u8 = MatMulNumM8(L_inv[i - 1][shiftindex[j]], temp_u8);
                temp_u8 = SBox[temp_u8 ^ expandedKey[16 * i + j]];
                temp_u32 = Tyi[j % 4][temp_u8];
                temp_u32 = MatMulNumM32(MB[i][columnindex[j]], temp_u32);
                TypeII[i][j][x] = (TypeII_out[i][j][0][(temp_u32 & 0xf0000000) >> 28] << 28) | (TypeII_out[i][j][1][(temp_u32 & 0x0f000000) >> 24] << 24) | (TypeII_out[i][j][2][(temp_u32 & 0x00f00000) >> 20] << 20) | (TypeII_out[i][j][3][(temp_u32 & 0x000f0000) >> 16] << 16) | (TypeII_out[i][j][4][(temp_u32 & 0x0000f000) >> 12] << 12) | (TypeII_out[i][j][5][(temp_u32 & 0x00000f00) >> 8] << 8) | (TypeII_out[i][j][6][(temp_u32 & 0x000000f0) >> 4] << 4) | (TypeII_out[i][j][7][(temp_u32 & 0x0000000f)]);
            }
        }
    
        for(j = 0; j < 16; j++)//type_III
        {
            u8 temp_u8;
            u32 temp_u32;
            int shiftbit[]={24, 16, 8, 0};
            for(x = 0; x < 256; x++)
            {
                temp_u8 = (TypeIV_II_out2_inv[i][columnindex[j]][(j % 4) * 2][(x & 0xf0) >> 4] << 4) | (TypeIV_II_out2_inv[i][columnindex[j]][(j % 4) * 2 + 1][(x & 0x0f)]);
                temp_u32 = temp_u8 << shiftbit[j % 4];
                temp_u32 = MatMulNumM32(MB_inv[i][columnindex[j]], temp_u32);
                temp_u32 = MatMulNumM32(Out_L[i][columnindex[j]], temp_u32);
                TypeIII[i][j][x] = (TypeIII_out[i][j][0][(temp_u32 & 0xf0000000) >> 28] << 28) | (TypeIII_out[i][j][1][(temp_u32 & 0x0f000000) >> 24] << 24) | (TypeIII_out[i][j][2][(temp_u32 & 0x00f00000) >> 20] << 20) | (TypeIII_out[i][j][3][(temp_u32 & 0x000f0000) >> 16] << 16) | (TypeIII_out[i][j][4][(temp_u32 & 0x0000f000) >> 12] << 12) | (TypeIII_out[i][j][5][(temp_u32 & 0x00000f00) >> 8] << 8) | (TypeIII_out[i][j][6][(temp_u32 & 0x000000f0) >> 4] << 4) | (TypeIII_out[i][j][7][(temp_u32 & 0x0000000f)]);
            }
        }
    }

    //Round 10
    shiftRows (expandedKey + 16 * 9);
    for(j = 0; j < 16; j++)//type_II
    {
        u8 temp_u8;
        for(x = 0; x < 256; x++)
        {
            temp_u8 = (TypeIV_III_out2_inv[8][columnindex[shiftindex[j]]][(shiftindex[j] % 4) * 2][(x & 0xf0) >> 4] << 4) | (TypeIV_III_out2_inv[8][columnindex[shiftindex[j]]][(shiftindex[j] % 4) * 2 + 1][(x & 0x0f)]);
            temp_u8 = MatMulNumM8(L_inv[8][shiftindex[j]], temp_u8);
            temp_u8 = SBox[temp_u8 ^ expandedKey[16 * 9 + j]] ^ expandedKey[16 * 10 + j];
            temp_u8 = MatMulNumM8(ex_out[j], temp_u8);
            TypeII[9][j][x] = (TypeIII_ex_out[j][0][(temp_u8 & 0xf0) >> 4] << 4) | (TypeIII_ex_out[j][1][(temp_u8 & 0x0f)]);
        }
    }

    for(i = 0; i < 9; i++)
    {
        for(j = 0; j < 4; j++)
        {
            for(k = 0; k < 8; k++)
            {
                for(x = 0; x < 16; x++)
                {
                    for(y = 0; y < 16; y++)
                    {
                        TypeIV_II[i][j][0][k][x][y] = TypeIV_II_out1[i][2 * j][k][TypeII_out_inv[i][4 * j][k][x] ^ TypeII_out_inv[i][4 * j + 1][k][y]];
                        TypeIV_II[i][j][1][k][x][y] = TypeIV_II_out1[i][2 * j + 1][k][TypeII_out_inv[i][4 * j + 2][k][x] ^ TypeII_out_inv[i][4 * j + 3][k][y]];
                        TypeIV_II[i][j][2][k][x][y] = TypeIV_II_out2[i][j][k][TypeIV_II_out1_inv[i][2 * j][k][x] ^ TypeIV_II_out1_inv[i][2 * j + 1][k][y]];

                        TypeIV_III[i][j][0][k][x][y] = TypeIV_III_out1[i][2 * j][k][TypeIII_out_inv[i][4 * j][k][x] ^ TypeIII_out_inv[i][4 * j + 1][k][y]];
                        TypeIV_III[i][j][1][k][x][y] = TypeIV_III_out1[i][2 * j + 1][k][TypeIII_out_inv[i][4 * j + 2][k][x] ^ TypeIII_out_inv[i][4 * j + 3][k][y]];
                        TypeIV_III[i][j][2][k][x][y] = TypeIV_III_out2[i][j][k][TypeIV_III_out1_inv[i][2 * j][k][x] ^ TypeIV_III_out1_inv[i][2 * j + 1][k][y]];
                    }
                }
            }
        }
    }

    for(i = 0; i < 16; i++)
    {
        u8 temp_u8;
        for(x = 0; x < 256; x++)
        {
            temp_u8 = MatMulNumM8(ex_in[i], x);
            TypeIa[i][x] = (TypeII_ex_in[i][0][(temp_u8 & 0xf0) >> 4] << 4) | (TypeII_ex_in[i][1][(temp_u8 & 0x0f)]);
            temp_u8 = (TypeIII_ex_out_inv[i][0][(x & 0xf0) >> 4] << 4) | (TypeIII_ex_out_inv[i][1][(x & 0x0f)]);
            TypeIb[i][x] = MatMulNumM8(ex_out_inv[i], temp_u8);
        }
    }
    
    u8 *result = (u8 *)(ex_out);
    for (i = 0; i < 16; i++)
    {
        key[i] = result[i]; 
    }
}
