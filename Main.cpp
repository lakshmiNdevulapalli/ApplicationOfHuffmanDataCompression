/*
* This file is a test case to SHA1 test which calls SHA1Input with an exact multiple
* of 512 bits, plus a few error test checks
*/
#include "stdafx.h"
#include <stdio.h>
#include <string>
#include "Header.h"
#include "Huffman.h"
#include <iostream>
#include <fstream> 
#include <cstring>
#include <chrono>
#include <thread>

using namespace std;
using namespace std::this_thread;
using namespace std::chrono;

long int repeatcount[1] = { 1 };

/* Main function */
int main() {

	string huffmanText, lines;
	ifstream inputfile("huffman.txt", ios::out);
	while (getline(inputfile, lines)) {
		huffmanText = lines;
	}
	const char* input = huffmanText.c_str();

	buildHuffmanTree(input);

	string text, line;
	ifstream infile("Text.txt", ios::in);
	while (getline(infile, line)) {
		text = line;
	}

	ofstream outfile;
	outfile.open("messageDigest.txt", ios::out);


	const char* testarray[] = { text.c_str() };
	SHA1Context sha;
	int i, j, err;
	uint8_t Message_Digest[20];

	/* Perform SHA1 test */
	for (j = 0; j < 1; j++) {
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
				fprintf(stderr, "\n SHA1Input Error %d.\n", err);
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
			cout << "\nSHA-1 of Huffman Encoded String :\n";
			//string str = "";
			for (i = 0; i < 20; ++i)
			{
				printf("%02X ", Message_Digest[i]);
				int num = stoi(Message_Digest[i], 0, 16);
				outfile<< std::hex << Message_Digest[i] << endl;
			}
			printf("\n");
		}
	}
	//outfile.close();
	getchar();
	return 0;
}