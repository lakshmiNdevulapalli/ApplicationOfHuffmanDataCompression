/*
* This file is a test case to SHA1 test which calls SHA1Input with an exact multiple
* of 512 bits, plus a few error test checks
*/
#include <stdio.h>
#include <string.h>
#include "New_Seed_Header.h"

/*
* Define test patterns
*/
#define TEST1   "mississippi"
//huffman-D5 8B 85 9A 2A C4 44 30 8D 5C 18 19 ED DC A0 77 23 3B B8 2D
/* an exact multiple of 512 bits */
char *testarray[1] =
{
	TEST1
};
long int repeatcount[1] = { 1 };
/* Results of the 4 test cases */

/* Main function */
int main() {

	SHA1Context sha;
	int i, j, err;
	uint8_t Message_Digest[20];

	/* Perform SHA1 test */
	for (j = 0; j < 1; ++j) {
		err = SHA1Reset(&sha);
		if (err)
		{
			fprintf(stderr, "SHA1Reset Error %d.\n", err);
			break;    /* out of for j loop */
		}

		for (i = 0; i < repeatcount[j]; ++i)
		{
			err = SHA1Input(&sha,
				(const unsigned char *)testarray[j],
				strlen(testarray[j]));
			if (err)
			{
				fprintf(stderr, "SHA1Input Error %d.\n", err);
				break;    /* out of for i loop */
			}
		}
		err = SHA1Result(&sha, Message_Digest);
		if (err)
		{
			fprintf(stderr,
				"SHA1Result Error %d, could not compute message digest.\n",
				err);
		}
		else
		{
			printf("Our Observation - ");
			for (i = 0; i < 20; ++i)
			{
				printf("%02X ", Message_Digest[i]);
			}
			printf("\n");
		}
	}
	getchar();
	return 0;
}