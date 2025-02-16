/* SHA.c */
#include "SHA.h"

/* Convert the string to bytes -> returns a bytes */

uint8_t* toBytes(const char* input, size_t *length)
{
	*length = strlen(input);
	uint8_t* bytes = (uint8_t*)malloc(*length);
	
	if(!bytes)
	{
		perror("Memory allocation failed");
		return NULL;
	}
	memset(bytes, 0, *length);
	memcpy(bytes, input, *length);

	return bytes;

}


/* Give padding to the message */

uint8_t* padMessage(uint8_t* message, size_t length, size_t* paddedLength)
{
	uint64_t bitLength = length * 8;
	int i;
	size_t paddingLength = (512 + 448 - (bitLength + 1) % 512) % 512;
	*paddedLength = length + (paddingLength / 8) + 8;

	uint8_t* paddedMessage = (uint8_t*)calloc(*paddedLength, 1);
	if(!paddedMessage)
	{
		perror("Message allocation failed");
		return NULL;
	}
	
	memcpy(paddedMessage, message, length);
	paddedMessage[length] = 0x80;

	for(i=0; i<8; i++)
	{
		paddedMessage[*paddedLength - 1 - i] = (bitLength >> (i * 8)) & 0xFF;
	}

	return paddedMessage;
}

/* SHA-256 Compression Function */

void compressBlock(uint32_t* block, uint32_t* hash)
{
	uint32_t w[64], a, b, c, d, e, f, g, h, temp1, temp2, i;

	for(i=0; i<16; i++)
	{
		w[i] = (block[i] << 24) | ((block[i] & 0xff00) << 8) |
			((block[i] & 0xff0000) >> 8) | (block[i] >> 24);
	}
	
	for(i=16; i<64; i++)
	{
		uint32_t s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}


	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	e = hash[4];
	f = hash[5];
	g = hash[6];
	h = hash[7];
	
	for(i=0; i<64; i++)
	{
		uint32_t S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
		uint32_t ch = (e & f) ^ (~e & g);
		temp1 = h + S1 + ch + K[i] + w[i];

		uint32_t S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		temp2 = S0 + maj;

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;
	hash[5] += f;
	hash[6] += g;
	hash[7] += h;
}

/* Convert hash to hex */

void toHex(uint32_t* hash, char* output)
{
	int i;
	for(i=0; i<8; i++)
	{
		sprintf(output + (i * 8), "%08x", hash[i]);
	}
}

/* SHA-256 Hash Function */
char* sha256(const char* input)
{
	size_t length, paddedLength, i;
	uint8_t* message = toBytes(input, &length);
	uint8_t* paddedMessage = padMessage(message, length, &paddedLength);
	uint32_t hash[8];

	memset(hash, 0, sizeof(H));
	memcpy(hash, H, sizeof(H));

	for(i=0; i<paddedLength; i+=64)
	{
		compressBlock((uint32_t*)(paddedMessage + i), hash); 
	}

	char* output = (char*)malloc(65);
	toHex(hash, output);
	output[64] = '\0';

	free(message);
	free(paddedMessage);

	return output;
}

/* DJB2 hash Written by Daniel J. Bernstein (also known as djb), this simple hash function dates back to 1991.*/

unsigned long djb2_hash(char *str)
{
	unsigned long hash = 5381;
	int c;
	
	while((c = *(str++)))
	{
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}

	return hash;

}

/* The MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value. MD5 was designed by Ronald Rivest in 1991 to replace an earlier hash function MD4,[3] and was specified in 1992 as RFC 1321 */

void md5_hash(const char *str, uint8_t *digest) {
    uint32_t a0 = 0x67452301;
    uint32_t b0 = 0xefcdab89;
    uint32_t c0 = 0x98badcfe;
    uint32_t d0 = 0x10325476;

    size_t initial_len = strlen(str);
    size_t new_len = ((initial_len + 8) / 64 + 1) * 64;
    uint8_t *msg = calloc(new_len, 1);
    memcpy(msg, str, initial_len);
    msg[initial_len] = 0x80; /* Adding one bit */

    uint64_t bit_len = initial_len * 8;
    memcpy(msg + new_len - 8, &bit_len, 8);

    for (size_t offset = 0; offset < new_len; offset += 64) {
        uint32_t M[16];
        memcpy(M, msg + offset, 64);

        uint32_t A = a0, B = b0, C = c0, D = d0;

        for (uint32_t i = 0; i < 64; i++) {
            uint32_t F, g;
            if (i < 16) {
                F = (B & C) | (~B & D); 
                g = i;
            } else if (i < 32) {
                F = (D & B) | (~D & C);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                F = B ^ C ^ D;
                g = (3 * i + 5) % 16;
            } else {
                F = C ^ (B | ~D);
                g = (7 * i) % 16;
            }

            F = F + A + K[i] + M[g];
            uint32_t temp = D;
            D = C;
            C = B;
            B = B + LEFTROTATE(F, s[i]);
            A = temp;
        }

        a0 += A;
        b0 += B;
        c0 += C;
        d0 += D;
    }

    free(msg);
    memcpy(digest, &a0, 4);
    memcpy(digest + 4, &b0, 4);
    memcpy(digest + 8, &c0, 4);
    memcpy(digest + 12, &d0, 4);
}



int main(int argc, char *argv[]) 
{
	char input[128];

	
	printf("Enter the value: ");
	fflush(stdout);
	if(scanf("%127s", input) != 1)
	{
		perror("Allocation failed");
		return -1;
	}
	

	char* sha = sha256(input);
	unsigned long djb2 = djb2_hash(input);

	printf("felix Hash: %s\n", sha);
	printf("Djb2 Hash: %lu\n", djb2);

	uint8_t digest[16];
    	md5_hash(input, digest);
    
    	printf("MD5 Hash: ");
    	for (int i = 0; i < 16; i++)
        	printf("%02x", digest[i]);
    	printf("\n");
	free(sha);

	return 0;
}
