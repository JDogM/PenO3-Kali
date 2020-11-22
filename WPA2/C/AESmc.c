#include <stdio.h>

int main(void)
{
	unsigned char r[4] = {0xdb, 0x13, 0x53, 0x45};
	unsigned char a[4];
	unsigned char b[4];
	unsigned char h;

	for(int i = 0; i < 4; i++)
	{
		a[i] = r[i];

		h = (unsigned char) ((signed char) r[i] >> 7);

		b[i] = r[i] << 1;

		b[i] ^= (0x1b & h);
	}

	r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
	r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
	r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
	r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];

	printf("Value for r: %x %x %x %x\n", r[0], r[1], r[2], r[3]);

	return 0;
}
