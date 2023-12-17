#include <stdio.h>

int main() {

	unsigned char s[32] = {0x04, 0x0b, 0x1f, 0x14, 0x1a, 0x15, 0x09, 0x02,
 0x1b, 0x05, 0x08, 0x12, 0x1d, 0x03, 0x06, 0x1c, 
 0x1e, 0x13, 0x07, 0x0e, 0x00, 0x0d, 0x11, 0x18,
 0x10, 0x0c, 0x01, 0x19, 0x16, 0x0a, 0x0f, 0x17};

	for( unsigned char x = 0; x < 32; ++x ) {
		
		printf("for the value x = %02x\n", x);

		printf("with input difference:: 1\n");
		printf("output difference:%02x\n", s[x]^s[x^0x01]);

		printf("with input difference:: 2\n");
                printf("output difference:%02x\n", s[x]^s[x^0x02]);

		printf("with input difference:: 4\n");
                printf("output difference:%02x\n", s[x]^s[x^0x04]);

		printf("with input difference:: 8\n");
                printf("output difference:%02x\n", s[x]^s[x^0x08]);

		printf("with input difference:: 0x10\n");
                printf("output difference:%02x\n", s[x]^s[x^0x10]);

		printf("..........................................................\n\n");
	}

	return 0;
}
