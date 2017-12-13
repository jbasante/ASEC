#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include "sha256.h"

/****************************** MACROS ******************************/
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/

//Hard coded expected message in binary. Hexadecimal hash is converted to binary and compared to this.
BYTE *expectedHash[SHA256_BLOCK_SIZE] = {
  "00100100", "10001101", "01101010", "01100001", "11010010", "00000110", "00111000", "10111000", "11100101", "11000000", "00100110", "10010011", "00001100", "00111110", "01100000", "00111001", "10100011", "00111100", "11100100", "01011001", "01100100", "11111111", "00100001", "01100111", "11110110", "11101100", "11101101", "11010100", "00011001", "11011011", "00000110", "11000001"
};

static const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DEFINITIONS ***********************/

/* Function: Does the actual hashing of the message
 * Parameters: Data manipulating struct and an array
 * Return: void 
 */
void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}


/* Function: Initializes the hash
 * Parameters: The data manipulating struct
 * Return: void
 */
void sha256_init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

/* Function: Updates the hash after initialization.
 * Parameters: Pointer to a data manipulating struct
 * Return: void
 */
void sha256_update(SHA256_CTX *ctx, const BYTE *data, size_t len)
{
	WORD i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

/* Function: Finalizes the hashing 
 * Parameters: Pointer to data manipulating struct and a buffer
 * Return: void 
 */
void sha256_final(SHA256_CTX *ctx, BYTE *hash)
{
	WORD i;
	char *hashBinary;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
	
	//print hash value
	
	printf("\nHash: \t");
	for(i = 0; i < SHA256_BLOCK_SIZE; i++){
	  printf("%02X ", (unsigned)hash[i]);
	}

}

/* Function: Creates the hash value of a string
 * Parameters: A message, a struct , a buffer and a temporary holder of the message
 * Return: 1 if hash is successfully created, or 0
 */
int createMessageHash(char *Message,	SHA256_CTX ctx, BYTE *hashBuff, char *message_byte){

	if((message_byte = (char *)malloc(sizeof(char *)*strlen(message_byte))) == NULL){
	  printf("Could not allocate memory. Exiting ...\n");
	  return 0;
	}
	
	if (!strcpy(message_byte, (const char *)Message)){
	  printf("Could not parse message. Now exiting...\n");
	  return 0;
	}
	
	printf("Message: \t%s\n", message_byte);
	
	printf("\nLength: \t%d\n", strlen(message_byte));

	
	sha256_init(&ctx);
	sha256_update(&ctx, (const)message_byte, strlen(message_byte));
	sha256_final(&ctx, hashBuff);
	
	free(message_byte);
	return 1;
}

/* Function: Combines the hashing of a message and checking with expected hash value.
 * Parameters: The message to be hashed and verified
 * Returns: 1 if hash and check are both successful, 0 if either are not successful
 */
int hashAndCheck(char *inputMessage)
{
	BYTE *buf;
	char *m_byte;
	SHA256_CTX ctx;
	int idx, i;
	int pass = 1;
	
	if (!createMessageHash(inputMessage, ctx, &buf, m_byte)){
	    printf("Could not create hash\n");
	    return 0;
	}
	else
	    printf("\n\nHash successfully created\n");
	  
	if(!hashesMatch(&buf)){
	   printf("\nNo Match\n");
	   return 0;
  }
	else{
	   printf("\nMatch\n");
	}

	return 1;
}

/* Function: Checks if the calculated hash of the message matches the expected hash.
 * Parameters: A 32 byte hash value
 * Return: Returns 1 if the calculated hash matches the expected hash, or returns 0
 */

int hashesMatch(BYTE *hash){
  char *hashBinary;
  int hashConstant = 1;
  int i;
  
  for(i = 0; i < SHA256_BLOCK_SIZE; i++){
	    hashBinary = convert(&hash[i]);
	    hashConstant &= !strcmp(hashBinary, expectedHash[i]);
	}
	
	return hashConstant;
}

/*
 * Function: Converts a hexadecimal to a binary string
 * Parameters: A hexadecimal as a part of the message digest (hash)
 * Return: eight bit binary
 */
char *convert(BYTE *hexValue)
{
  char* hexbuffer;
  int i;

  hexbuffer = malloc(9);
  if (!hexbuffer)
    return NULL;

  hexbuffer[8] = 0;
  for (i = 0; i <= 7; i++)
    hexbuffer[7 - i] = (((*hexValue) >> i) & (0x01)) + '0';

  //puts(hexbuffer);

  return hexbuffer;
}

