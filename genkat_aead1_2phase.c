//This source is taken from the NIST lightweight competition. We have modified it according to our requirements. 

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <inttypes.h>

#include "crypto_aead.h"
#include "api.h"
#include "permutations.h"

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

#define MAX_FILE_NAME				256
#define MAX_MESSAGE_LENGTH			32
#define MAX_ASSOCIATED_DATA_LENGTH	32
#define sboxSize 32

typedef unsigned char u8;
//typedef unsigned long long u64;
typedef uint64_t u64;

unsigned char s[32] = {0x04, 0x0b, 0x1f, 0x14, 0x1a, 0x15, 0x09, 0x02,
 0x1b, 0x05, 0x08, 0x12, 0x1d, 0x03, 0x06, 0x1c, 
 0x1e, 0x13, 0x07, 0x0e, 0x00, 0x0d, 0x11, 0x18,
 0x10, 0x0c, 0x01, 0x19, 0x16, 0x0a, 0x0f, 0x17};

void init_buffer(unsigned char *buffer, unsigned long long numbytes);

void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length);

int generate_test_vectors();

int main()
{
	int ret = generate_test_vectors();

	if (ret != KAT_SUCCESS) {
		fprintf(stderr, "test vector generation failed with code %d\n", ret);
	}

	return ret;
}

void print_ct( unsigned char *m ) {

	printf("Ciphertext::\n");
	for( short i = 0; i < 32; ++i )
		printf("%02x ", m[ i ]);
		
	printf("\n\n");
	
	printf("Tag::\n");
	for( short i = 32; i < 48; ++i )
		printf("%02x ", m[ i ]);
		
	printf("\n\n");

	return;
}

void print_msg( unsigned char *m ) {

	printf("Plaintext::\n");
	for( short i = 0; i < 32; ++i )
		printf("%02x ", m[ i ]);
		
	printf("\n\n");
	
	return;
}


void printDDT( unsigned char **ptr ) {


	for( int i = 0; i < 32; ++i ) {

		for( int j = 0; j < 32; ++j ) {

			printf("%2d ", ptr[ i ][ j ]);
		}
		printf("\n");
	}

	return;
}


unsigned char **diffDistribution(unsigned char s[sboxSize]) {

	int i; 
	int x, y, delta, delta1;
	
	unsigned char** count = malloc(sboxSize*sizeof(int *));
	
	for(i = 0; i < sboxSize; ++i) {
		
		count[i] = malloc(sboxSize*sizeof(int));
		memset(count[i],0,sboxSize*sizeof(int));
	}
		
	for(y = 0; y < sboxSize; ++y) {
		
		for(x = 0; x < sboxSize; ++x) {
			
			delta = y^x;
			delta1 = s[x]^s[y];
			count[delta][delta1]++;
		}		
	}
	
	return count;
}


unsigned char search_with_bit(unsigned char *td, unsigned char ptr[16][6], unsigned char bit, unsigned char ptr1[16][2]) {

    unsigned char input[2], final_input;
    short index = 0;
    for(short i = 0; i < 16; ++i) {
        
        if( (td[0] == ptr[i][0]) && (td[1] == ptr[i][1]) && (td[2] == ptr[i][2]) && (td[3] == ptr[i][3]) && (td[4] == ptr[i][4])) {
        
            //printf("input = %02x %02x\n", ptr1[i][5], ptr1[i][5]);
            input[index] = ptr1[i][0];
            input[index+1] = ptr1[i][1];
            //printf("input = %02x %02x\n", ptr1[i][0], ptr1[i][1]);
            break;
        }
    }
    
    //printf("input0, input1 = %02x %02x\n", input[0], input[1]);
    //printf("not found");
    
    if( ( ( ( input[0] ) & 0x04 ) >> 2 ) == bit )
        return (s[input[0]]);
    if( ( ( ( input[1] ) & 0x04 ) >> 2 ) == bit )
        return (s[input[1]]);
}


unsigned char search(unsigned char *td, unsigned char ptr[16][6]) {

    for(short i = 0; i < 16; ++i) {
        
        if( (td[0] == ptr[i][0]) && (td[1] == ptr[i][1]) && (td[2] == ptr[i][2]) && (td[3] == ptr[i][3]) && (td[4] == ptr[i][4])) {
        
            //printf("input0 = %02x\n", i);
            return ptr[i][5];
        }
    }
    printf("not found");
    return 5;
}



int generate_test_vectors()
{
	FILE                *fp;
	char                fileName[MAX_FILE_NAME];
	unsigned char       key[CRYPTO_KEYBYTES] = {0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x31, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0xf1};
	unsigned char		nonce[CRYPTO_NPUBBYTES] = {0x12, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0xf1};
	unsigned char       msg[MAX_MESSAGE_LENGTH] = {0x12, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0xf1, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0xf1};
	unsigned char       msg2[MAX_MESSAGE_LENGTH];
	unsigned char		ad[MAX_ASSOCIATED_DATA_LENGTH] = {0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0xf1};
	unsigned char		ct[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES], ct1[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES] = {0};
	unsigned long long  mlen, mlen2, clen, adlen;
	int                 count = 1;
	int                 func_ret, ret_val = KAT_SUCCESS;
	
	unsigned char **ddt = diffDistribution(s);
	
	unsigned char ftag[16] = {0};
	unsigned char msb_diff_set[] = {0x09, 0x0b, 0x18, 0x1a};
	//unsigned char snd_msb_diff_set[] = {0x06, 0x07, 0x0e, 0x0f, 0x16, 0x17, 0x1e, 0x1f};
	unsigned char snd_msb_diff_set[] = {0x00, 0x01, 0x10, 0x11};
	
	short col_diff_pos, row_diff_pos;
	
	time_t t;
	srand( (unsigned) time( &t ) );
	
	col_diff_pos = rand()%64;
	row_diff_pos = rand()%4;
	
	typedef struct {
        u64 d0, d1, d2, d3, d4;
    } diff;
    
    diff d;
    
    d.d0 = 0;
    d.d1 = 0;
    d.d2 = 0;
    d.d3 = 0;
    d.d4 = 0;
    
    
    unsigned char table[16][6] = {{0x01, 0x11, 0x01, 0x11, 0x11, 0x0}, 
{0x00, 0x01, 0x01, 0x11, 0x11, 0x1}, 
{0x00, 0x11, 0x01, 0x11, 0x11, 0x1}, 
{0x01, 0x01, 0x01, 0x11, 0x11, 0x0}, 
{0x11, 0x11, 0x01, 0x11, 0x01, 0x1}, 
{0x10, 0x01, 0x01, 0x11, 0x01, 0x1}, 
{0x10, 0x11, 0x01, 0x11, 0x01, 0x0}, 
{0x11, 0x01, 0x01, 0x11, 0x01, 0x0}, 
{0x01, 0x01, 0x01, 0x10, 0x10, 0x0}, 
{0x00, 0x11, 0x01, 0x10, 0x10, 0x1}, 
{0x00, 0x01, 0x01, 0x10, 0x10, 0x1}, 
{0x01, 0x11, 0x01, 0x10, 0x10, 0x0}, 
{0x11, 0x01, 0x01, 0x10, 0x00, 0x0}, 
{0x10, 0x11, 0x01, 0x10, 0x00, 0x0}, 
{0x10, 0x01, 0x01, 0x10, 0x00, 0x1}, 
{0x11, 0x11, 0x01, 0x10, 0x00, 0x1}};

    unsigned char Sbx_input_pairs[16][2] = {{0,4}, {1,5}, {2,6}, {3,7}, {8,0x0c}, {9,0x0d}, {0x0a,0x0e}, {0x0b,0xf}, {0x10,0x14}, {0x11,0x15}, {0x12,0x16}, {0x13,0x17}, {0x18,0x1c}, {0x19,0x1d}, {0x1a,0x1e}, {0x1b,0x1f}};

    for(short i = 0; i < 16; ++i) {
        for(short j = 0; j < 6; ++j)
            printf("%02x ", table[i][j]);
        printf("\n");
    }


	init_buffer(key, sizeof(key));
	init_buffer(nonce, sizeof(nonce));
	init_buffer(msg, sizeof(msg));
	init_buffer(ad, sizeof(ad));
	
	printDDT( &ddt[ 0 ] );
	
	mlen = adlen = mlen2 = 32;
	clen = 48;
	
	printf("msg len = %d\n", sizeof(msg));
	print_msg(msg);
	
	printf("...............Encryption.....................\n");
	if ( crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key) == 0)
		print_ct(ct);
		
	if ( crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key) == 0) {
	
		print_ct(ct);
		printf("Decryption is successful!!\n\n\n");
	}
	else
		printf("Not successful!!\n\n\n");
		
	unsigned char tag_diff[5][64], rkey1[64],rkey2[64];
	u64 key_ret = 0;
	/******************************* 1st phase attack **************************************************/
	for(int j = 0; j < 64; ++j) {
	    for(int k = 0; k < 5; ++k) {
	    
	        col_diff_pos = j;
	        row_diff_pos = k;
	        //printf("-------------------------For new row, col pos::%d,%d---------------------------------\n", row_diff_pos, col_diff_pos);
	        for(int df_ctr = 0; df_ctr < 4; ++df_ctr) {
	            //printf(".............................................\n");
	            unsigned char df_val = snd_msb_diff_set[df_ctr];
	            unsigned char df_val1 = snd_msb_diff_set[df_ctr];
	            df_val = ((df_val >> 0) & 0x01);
	            df_val1 = ((df_val1 >> 4) & 0x01);
	            //printf("df_ctr = %d, df_val = %x, df_val1 = %x\n", df_ctr, df_val, df_val1);
	            uint64_t df3, df4;
	            if(df_val == 1)
	                d.d3 = (1ULL << (63-col_diff_pos));
	            else
	                d.d3 = 0;
	               
	            if(df_val1 == 1)
	                d.d4 = (1ULL << (63-col_diff_pos));
	            else
	                d.d4 = 0;
	            //printf("df_val = %x, df_val1 = %x, %016"PRIx64", %016"PRIx64"\n", df_val, df_val1, df3, df4);
		        
	            /*d.d3 = df3;
	            d.d4 = df4;*/
	            //printf("d.d3 = %016"PRIx64", d.d4 = %016"PRIx64"\n", d.d3, d.d4);
	            
	            d.d0 ^= ROTR64(d.d0, 19) ^ ROTR64(d.d0, 28);
                d.d1 ^= ROTR64(d.d1, 61) ^ ROTR64(d.d1, 39);
                d.d2 ^= ROTR64(d.d2, 1) ^ ROTR64(d.d2, 6);
                d.d3 ^= ROTR64(d.d3, 10) ^ ROTR64(d.d3, 17);
                d.d4 ^= ROTR64(d.d4, 7) ^ ROTR64(d.d4, 41);
                
                //printf("d.d3 = %016"PRIx64", d.d4 = %016"PRIx64"\n", d.d3, d.d4);
                
                for(int i = 32; i < 48; ++i)
                    ftag[i-32] = ct[i];
                    
                U64_TO_BYTES(ftag, d.d3, 8);
                U64_TO_BYTES(ftag+8, d.d4, 8);
                
                /*for(int i = 0; i < 16; ++i)
                    printf("ftag[%d] = %x\n", i, ftag[i]);
                printf("\n");*/
                
                for(int i = 0; i < 48; ++i)
                    ct1[i] = ct[i];
                
                for(int i = 32; i < 48; ++i)
                    ct1[i] ^= ftag[i-32];
	               	
	            if ( crypto_aead_decrypt_fault(msg2, &mlen2, NULL, ct1, clen, ad, adlen, nonce, key, col_diff_pos, row_diff_pos) == 0) {
	            
	                //print_ct(ct);
		            //print_ct(ct1);
		            //printf("\nDecryption is successful!!\n\n\n");
		            tag_diff[k][j] = (df_val1 << 4) ^ df_val;
	            }
	            else {
	                ;
	                //print_ct(ct1);
		            //printf("\nNot successful!!\n\n\n");
	            }
	            
	        }
	    }
	    
	    /*printf("First two lsb bit difference pattern for each 5 bit-flip faults::\n");
	    for(short i = 0; i < 5; ++i)
	        printf("%02x ", tag_diff[i][j]);
	    printf("\n");*/
	    unsigned char td[5];
	    for(short i = 0; i < 5; ++i)
	        td[i] = tag_diff[i][j];
	    rkey2[j] = search(&td[0], table);
	    //printf("\n\n");
	}
	
	printf("original key (K_0||K_1)::\n");
	for(short i = 0; i < 16; ++i)
	    printf("%x, ", key[i]);
	printf("\n");
	
	/*printf("Original 128 bit state (capacity part X_3||X_4) before the last Key XOR to output the final tag::\n");
	for(short i = 0; i < 16; ++i) {
	
	    printf("%x, ", key[i]^ct[32+i]);
	   
	}
	printf("\n");*/
	
	//printf("\n64 bit state X_4 retrieved from the faulty forgery::\n");
	for(short i = 0; i < 64; ++i) {
	    //printf("%x ", rkey2[i]);
	    if(i < 63) {
	    
	        key_ret ^= rkey2[i];
	        key_ret = (key_ret << 1); 
	    }
	    else
	        key_ret ^= rkey2[i];
	}
	
	key_ret ^= ROTR64(key_ret, 7) ^ ROTR64(key_ret, 41);
	//printf("\n\nRetrieved 64 bit state (capacity part:: X_4) before the last Key XOR in the final tag::\n");
	//printf("key_ret = %016"PRIx64"\n", key_ret);
	unsigned char retrieved_key2[16];
	U64_TO_BYTES(retrieved_key2, key_ret, 16);
	
	for(short i = 0; i < 16; ++i) {
	
	    retrieved_key2[i] ^= ct[32+i];
	}
	
	printf("\nLast 64-bit retrieved key K_1::\n");
	for(short i = 8; i < 16; ++i) {
	
	    printf("%x, ", retrieved_key2[i]);
	   
	}
	printf("\n");
	
	/********************************************************** 2nd phase attack ***************************************************/
	unsigned char X2[64];
	for(int j = 0; j < 64; ++j) {
	    
	        col_diff_pos = j;
	        row_diff_pos = 2;
	        //printf("-------------------------For new row, col pos::%d,%d---------------------------------\n", row_diff_pos, col_diff_pos);
	        //for(int df_ctr = 0; df_ctr < 4; ++df_ctr) {
	            //printf(".............................................\n");
	            //printf("%02x \n", tag_diff[3][j]);
	            unsigned char df_val = tag_diff[2][j];
	            unsigned char df_val1 = tag_diff[2][j];
	            df_val = ((df_val >> 0) & 0x01);
	            df_val1 = ((df_val1 >> 4) & 0x01);
	            //printf("df_ctr = %d, df_val = %x, df_val1 = %x\n", df_ctr, df_val, df_val1);
	            uint64_t df3, df4;
	            if(df_val == 1)
	                d.d3 = (1ULL << (63-col_diff_pos));
	            else
	                d.d3 = 0;
	               
	            if(df_val1 == 1)
	                d.d4 = (1ULL << (63-col_diff_pos));
	            else
	                d.d4 = 0;
	            //printf("df_val = %x, df_val1 = %x, %016"PRIx64", %016"PRIx64"\n", df_val, df_val1, df3, df4);
		        
	            //printf("d.d3 = %016"PRIx64", d.d4 = %016"PRIx64"\n", d.d3, d.d4);
	            
	            d.d0 ^= ROTR64(d.d0, 19) ^ ROTR64(d.d0, 28);
                d.d1 ^= ROTR64(d.d1, 61) ^ ROTR64(d.d1, 39);
                d.d2 ^= ROTR64(d.d2, 1) ^ ROTR64(d.d2, 6);
                d.d3 ^= ROTR64(d.d3, 10) ^ ROTR64(d.d3, 17);
                d.d4 ^= ROTR64(d.d4, 7) ^ ROTR64(d.d4, 41);
                
                //printf("d.d3 = %016"PRIx64", d.d4 = %016"PRIx64"\n", d.d3, d.d4);
                
                for(int i = 32; i < 48; ++i)
                    ftag[i-32] = ct[i];
                    
                U64_TO_BYTES(ftag, d.d3, 8);
                U64_TO_BYTES(ftag+8, d.d4, 8);
                
                //for(int i = 0; i < 16; ++i)
                //    printf("ftag[%d] = %x\n", i, ftag[i]);
                //printf("\n");
                
                for(int i = 0; i < 48; ++i)
                    ct1[i] = ct[i];
                
                for(int i = 32; i < 48; ++i)
                    ct1[i] ^= ftag[i-32];
	               	
	            if ( crypto_aead_decrypt_fault_bit_set(msg2, &mlen2, NULL, ct1, clen, ad, adlen, nonce, key, col_diff_pos, row_diff_pos) == 0) {
	            
	                //print_ct(ct);
		            //print_ct(ct1);
		            //printf("\nDecryption is successful!!\n\n\n");
		            X2[j] = 0x0;
	            }
	            else {
	                //print_ct(ct1);
		            //printf("\nNot successful!!\n\n\n");
		            X2[j] = 0x1;
	            }
	            
	        //}
	    
	    /*printf("First two lsb bit difference pattern for each 5 bit-flip faults::\n");
	    for(short i = 0; i < 5; ++i)
	        printf("%02x ", tag_diff[3][j]);
	    printf("\n");*/
	    unsigned char td[5];
	    for(short i = 0; i < 5; ++i)
	        td[i] = tag_diff[i][j];
	    rkey1[j] = search_with_bit(&td[0], table, X2[j], Sbx_input_pairs);
	    //printf("\n\n");
	}
	
	/*printf("original key::\n");
	for(short i = 0; i < 16; ++i)
	    printf("%x, ", key[i]);
	printf("\n\n");*/
	
	/*printf("Original 128 bit state (capacity part X_3||X_4) before the last Key XOR to output the final tag::\n");
	for(short i = 0; i < 16; ++i) {
	
	    printf("%x, ", key[i]^ct[32+i]);
	   
	}
	printf("\n");*/
	
	key_ret = 0x0;
	//printf("\n64 bit state X_4 retrieved from the faulty forgery::\n");
	for(short i = 0; i < 64; ++i) {
	    //printf("%x ", rkey1[i]);
	    if(i < 63) {
	    
	        key_ret ^= ((rkey1[i] & 0x02) >> 1);
	        key_ret = (key_ret << 1); 
	    }
	    else
	        key_ret ^= ((rkey1[i] & 0x02) >> 1);
	}
	
	key_ret ^= ROTR64(key_ret, 10) ^ ROTR64(key_ret, 17);
	//printf("\n\nRetrieved 64 bit state (capacity part:: X_4) before the last Key XOR in the final tag::\n");
	//printf("key_ret = %016"PRIx64"\n", key_ret);
	unsigned char retrieved_key1[16];
	U64_TO_BYTES(retrieved_key1, key_ret, 16);
	
	for(short i = 0; i < 16; ++i) {
	
	    retrieved_key1[i] ^= ct[32+i];
	}
	
	printf("\nFirst 64-bit retrieved key K_0::\n");
	for(short i = 0; i < 8; ++i) {
	
	    printf("%x, ", retrieved_key1[i]);
	   
	}
	printf("\n");
	
	printf("\nFull 128-bit retrieved key K_0||K_1::\n");
	for(short i = 0; i < 8; ++i) {
	
	    printf("%x, ", retrieved_key1[i]);
	   
	}
	for(short i = 8; i < 16; ++i) {
	
	    printf("%x, ", retrieved_key2[i]);
	   
	}
	printf("\n");
	

	return ret_val;
}


void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length)
{    
    fprintf(fp, "%s", label);
        
	for (unsigned long long i = 0; i < length; i++)
		fprintf(fp, "%02X", data[i]);
	    
    fprintf(fp, "\n");
}

void init_buffer(unsigned char *buffer, unsigned long long numbytes)
{
    time_t t;
	srand( (unsigned) time( &t ) );
	for (unsigned long long i = 0; i < numbytes; i++)
		buffer[i] = (unsigned char)rand()%256;//(unsigned char)i;
}
