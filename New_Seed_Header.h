#pragma once

/*
* Header file for sha code
* reference: US Secure Hash Algorithm 1 by Network working group
*/

/* This Header will decalre set of integer types having specified
* widths. Width of an integer type is the numnber of bits used to
* store its value in a pure binary system.
*
* The actual type may use more bits that that. for example, a 28-bit type could store
* in 32-bit of actual storage.
*/
#include <stdint.h>

/*
* enum is a user-defined data type that consists of integral constants.
*/
enum
{
	shaOk = 0,
	shaNull, /* Null pointer parameter */
	shaInputLong, /* long input data */
	shaError /* called after result */
};

#define Sha1HashSize 20

/*
* This structure will hold the context information for the SHA-1 hash operation
* typedef is a reserved keyword. By defining the typedef, it is assured that all
* the variables are structure pointer types, or each variable is a pointer type
* pointing to a structure type.
*/
/*
* uint32_t -----> unsigned 32 bit integer
* uint8_t -----> unsigned 8 bit integer
*/
typedef struct SHA1Context
{
	uint32_t Intermediate_Hash[Sha1HashSize / 4]; /* Message Digest  */

	uint32_t Length_Low;            /* Message length in bits      */
	uint32_t Length_High;           /* Message length in bits      */

									/* Index into message block array   */
	int_least16_t Message_Block_Index;
	uint8_t Message_Block[64];      /* 512-bit message blocks      */

	int Computed;               /* Is the digest computed?         */
	int Corrupted;             /* Is the message digest corrupted? */
} SHA1Context; /*is the message digest corrupted ? */

			   /*
			   * Function Prototypes
			   */
int SHA1Reset(SHA1Context *);
int SHA1Input(SHA1Context *, const uint8_t *, unsigned int);
int SHA1Result(SHA1Context *,
uint8_t Message_Digest[Sha1HashSize]); 
