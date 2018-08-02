/*
* Description: this file implements the SHA1
* SHA1 produces 1 160-bit message digest for a given input
* SHA1 is defined in terms of 32-bit words. This code uses Header.h file
* to define 32-bit and 8-bit unsined integer types.
* This code only works with message with length that is a multiple of the size of an
* 8-bit character
*/

#include "New_Seed_Header.h"
#include <iostream>
#include <vector>
#include <string>
#include <sstream>  
#include <fstream>
#include <cstring>

using namespace std;

/* Method to assign message block numbers from 36 to 55*/
int assignBlockNumber = 0;
int text(int value) {

	for (int a = value + 1; a < 56; ) {
		assignBlockNumber = a;
		a++;
		break;

	}
	return(assignBlockNumber);
}

/* Dynamic vector holds the string values and
* Identifies the values by whitespaces in between them.
* returns the hash values after delimitng.
*/
vector<string> split(string str, char delimiter) {
	vector<string> inputHashValue;
	stringstream ss(str); // Turn the string into a stream.
	string tok;

	while (getline(ss, tok, delimiter)) {
		inputHashValue.push_back(tok);
	}

	return inputHashValue;
}


/*
* Define the SHA1 circular left shift
*
* The circular left shift operation S^n(X), where X is a word and n is an integer
* with 0 <= n < 32
*
* X << n is obtained as follows - discard the left-most n bits of X and then pad the
* result with n zeros on the right( the result will still be 32-bits).
*
* X >> 32- n is obtained by discarding the right-most n bits of X and then padding
* the result with n zeros on the left. Thus S^n(X) is equivalent to a circular shift
* of X by n postions to the left.
*/
#define SHA1CircularShift(bits,word) \
                (((word) << (bits)) | ((word) >> (32-(bits))))

/* Local Function Prototypes */
void SHA1PadMessage(SHA1Context *);
void SHA1ProcessMessageBlock(SHA1Context *);

/*
* SHA1 Reset
*
* This function will initialize the SHA1Context in preparation for computing
* a new SHA1 message digest.
*
* It initializes Length_Low, Length_High and Message_block_index to zero
*
* Returns SHA1 Error code
*/
int SHA1Reset(SHA1Context *context) {
	if (!context) {
		return shaNull;
	}
	context->Length_Low = 0;
	context->Length_High = 0;
	context->Message_Block_Index = 0;

	context->Intermediate_Hash[0] = 0x67452301;
	context->Intermediate_Hash[1] = 0xEFCDAB89;
	context->Intermediate_Hash[2] = 0x98BADCFE;
	context->Intermediate_Hash[3] = 0x10325476;
	context->Intermediate_Hash[4] = 0xC3D2E1F0;

	context->Computed = 0;
	context->Corrupted = 0;

	return shaOk;
}

/*
*  SHA1Result
*
*  Description:
*      This function will return the 160-bit message digest into the
*      Message_Digest array  provided by the caller.
*      NOTE: The first octet of hash is stored in the 0th element,
*            the last octet of hash in the 19th element.
*
*  Parameters:
*      context: [in/out]
*          The context to use to calculate the SHA-1 hash.
*      Message_Digest: [out]
*          Where the digest is returned.
*
*  Returns:
*      sha Error Code.
*
*/
int SHA1Result(SHA1Context *context,
	uint8_t Message_Digest[Sha1HashSize])
{
	int i;

	if (!context || !Message_Digest)
	{
		return shaNull;
	}

	if (context->Corrupted)
	{
		return context->Corrupted;
	}

	if (!context->Computed)
	{
		SHA1PadMessage(context);
		for (i = 0; i<64; ++i)
		{
			/* message may be sensitive, clear it out */
			context->Message_Block[i] = 0;
		}
		context->Length_Low = 0;    /* and clear length */
		context->Length_High = 0;
		context->Computed = 1;
	}

	for (i = 0; i < Sha1HashSize; ++i)
	{
		Message_Digest[i] = context->Intermediate_Hash[i >> 2]
			>> 8 * (3 - (i & 0x03));
	}

	return shaOk;
}


/*
* SHA1 Input
* Description: This function accepts an array of octects as the next portion of the
* message

* message_array is a parameter : An array of Characters representing the next
* portion of the message

* length: length of the message in message_array

* Returns SHA Error code
* If the number of bits in a message is a multiple of 8, for compactness we can represent the message in hex.
* The padded message will contain 16 * n words for some n > 0. The padded message is regarded as a sequence of n blocks M(1) , M(2), first characters (or bits) of the message.
*/
int SHA1Input(SHA1Context *context, const uint8_t *message_array, unsigned length) {
	if (!length) {			//condition for length
		return shaOk;
	}
	if (!context || !message_array) { //condition for no message array
		return shaNull;
	}
	if (context->Computed) {
		context->Corrupted = shaError; // condition to check corrupted bits
		return shaError;
	}
	if (context->Corrupted) {
		return context->Corrupted; // condition to check corrupted bits
	}
	while (length-- && !context->Corrupted)
	{
		context->Message_Block[context->Message_Block_Index++] = (*message_array & 0xFF);
		context->Length_Low += 8;
		if (context->Length_Low == 0) {
			context->Length_High++;
			if (context->Length_High == 0) {
				/* Message is too long*/
				context->Corrupted = 1;
			}
		}
		if (context->Message_Block_Index == 64) {
			SHA1ProcessMessageBlock(context);
		}
		message_array++;
	}
	return shaOk;
}

/*
* SHA1ProcessMessageBlock

* Description: This function will process the next 512 bits of the message stored
* in the Message_block array

* this function has no parameters and returns nothing
*/
void SHA1ProcessMessageBlock(SHA1Context *context) {
	const uint32_t K[] = {       /* Constants defined in SHA-1   */
		0x5A827999,
		0x6ED9EBA1,
		0x8F1BBCDC,
		0xCA62C1D6
	};

	int           t;                 /* Loop counter                */
	uint32_t      temp;              /* Temporary word value        */
	uint32_t      W[80];             /* Word sequence               */
	uint32_t      A, B, C, D, E;     /* Word buffers                */

									 /*
									 *  Initialize the first 16 words in the array W
									 * | is a bitwise or, example x |= 8 means x = x | 8
									 */
	for (t = 0; t < 16; t++)
	{
		W[t] = context->Message_Block[t * 4] << 24;
		W[t] |= context->Message_Block[t * 4 + 1] << 16;
		W[t] |= context->Message_Block[t * 4 + 2] << 8;
		W[t] |= context->Message_Block[t * 4 + 3];
	}

	for (t = 16; t < 80; t++)
	{
		W[t] = SHA1CircularShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
	}

	A = context->Intermediate_Hash[0];
	B = context->Intermediate_Hash[1];
	C = context->Intermediate_Hash[2];
	D = context->Intermediate_Hash[3];
	E = context->Intermediate_Hash[4];

	for (t = 0; t < 20; t++)
	{
		temp = SHA1CircularShift(5, A) +
			((B & C) | ((~B) & D)) + E + W[t] + K[0];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 20; t < 40; t++)
	{
		temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 40; t < 60; t++)
	{
		temp = SHA1CircularShift(5, A) +
			((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 60; t < 80; t++)
	{
		temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	context->Intermediate_Hash[0] += A;
	context->Intermediate_Hash[1] += B;
	context->Intermediate_Hash[2] += C;
	context->Intermediate_Hash[3] += D;
	context->Intermediate_Hash[4] += E;

	context->Message_Block_Index = 0;
}

/*
* SHA1PadMessage

* Description: According to SHA1 standard, the message must be padded to an even 512 bits.
* 160-bit hash value of Huffman compressed codes and 288 0's appended.
* The last 64 bits represent the length of the original message.
* This function will pad the message according to those rules by filling the Message_Block array accordingly.
*
* It will also call the ProcessMessageBlock function provided appropriately.
* When it returns, it can be assumed that the message digest has been computed.
*
* Parameters are context and the ProcessMessageBlock function
*
* returns nothing
*
* If the number of bits in a message is a multiple of 8, for compactness we can represent the message in hex
*/
void SHA1PadMessage(SHA1Context *context) {
	/*
	*  Check to see if the current message block is too small to hold
	*  the initial padding bits and length.  If so, we will pad the
	*  block, process it, and then continue padding into a second
	*  block.
	*/
	if (context->Message_Block_Index > 35)
	{
		while (context->Message_Block_Index < 64)
		{
			context->Message_Block[context->Message_Block_Index++] = 0;
		}

		SHA1ProcessMessageBlock(context);

		while (context->Message_Block_Index < 36)
		{
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
	}
	else
	{
		while (context->Message_Block_Index < 36)
		{
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
	}
	/* SHA-1 of Huffman compressed codes are taken as input*/
	string line;
	ifstream inputfile("Huffman_SHA1_input.txt", ios::out);
	if (inputfile.is_open())
	{
		int index = 0;
		while (std::getline(inputfile, line))
		{
			istream& getline(inputfile >> line);
		}
	}

	int blockNumber = 35;
	string startingNumber = "";
	vector<string> sep = split(line, ' '); //Dynamic vector holds the Hash values from text file.
	for (unsigned int i = 0; i < sep.size(); ++i) {
		startingNumber = sep[i];
		text(blockNumber); // Call Text function
		blockNumber = assignBlockNumber;
		int num = stoi(startingNumber, 0, 16); //Convert String to Hexadecimal
		context->Message_Block[assignBlockNumber] = num; //Assign hash values values to Blocks 36 to 55. 
	}

	/*
	*  Store the message length as the last 8 octets
	*/
	context->Message_Block[56] = context->Length_High >> 24;
	context->Message_Block[57] = context->Length_High >> 16;
	context->Message_Block[58] = context->Length_High >> 8;
	context->Message_Block[59] = context->Length_High;
	context->Message_Block[60] = context->Length_Low >> 24;
	context->Message_Block[61] = context->Length_Low >> 16;
	context->Message_Block[62] = context->Length_Low >> 8;
	context->Message_Block[63] = context->Length_Low;

	SHA1ProcessMessageBlock(context);
}