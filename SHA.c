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

int main(int argc, char *argv[]) 
{
	char input[128];
	printf("Enter the value: ");F;
	if(scanf("%127s", input) != 1)
	{
		perror("Allocation failed");
		return -1;
	}

	
	char* hash = sha256(input);
	printf("SHA-256 Hash: %s\n", hash);


	free(hash);

	return 0;
}
