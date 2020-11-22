#include <stdio.h>
#include <stdlib.h>
#include "aes.h"

int main(void)
{
	unsigned char s[4];		// Is de gedecrypte vector
	unsigned char a[4];		// Is de encrypte vector uit bijv AERRijndeal.c

	unsigned char q[4][4] = 	// Is het inv(GF(2^8))
		{
			{0x0e, 0x0b, 0x0d, 0x09},
			{0x09, 0x0e, 0x0b, 0x0d},
			{0x0d, 0x09, 0x0e, 0x0b},
			{0x0b, 0x0d, 0x09, 0x0e}
		};

	for(int i = 0; i < sizeof(q[1]); i++)
	{
		multiplication(q, a, s);
	}

	return 0;
}

void multiplication(unsigned char** q, unsigned char* a, unsigned char *s)
{
	unsigned char* result;
	result = (unsigned char*) malloc(64 * sizeof(char));

	unsigned char* a_bin;
	a_bin = (unsigned char*) malloc(64 * sizeof(char));

	unsigned char* q_bin;
	q_bin = (unsigned char*) malloc(64 * sizeof(char));

	// Omzetten naar binary
	binary(a_bin, a);
	binary(q_bin, q);

	// Eerst de verm van de veeltermen a en b
	for(unsigned int i = 0; i < sizeof(*q); i++)
	{
		printf("hello");
	}
}
