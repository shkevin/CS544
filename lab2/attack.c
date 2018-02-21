#include "attack.h"

#include <inttypes.h>

int main(int argc, char const *argv[])
{
	// cipherText cipherText;
	// printf("%s cipher = \n", cipherText.cipher);
	// char *test = "test";
	cipherText C;

	C.ciper = "text";
	C.cipherPrime = "\x00\0";

	printf("%llu", sizeof(C.cipherPrime));
	return 0;
}
