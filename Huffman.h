/*
* Huffman Data Compression Algorithm 
* Reference of code and notes taken from Techie-Delight and 
* Dr.Naveen garg's (IIT-Delhi) lecture.  
*/

#include <iostream>
#include <fstream> 
#include <cstring>
#include <chrono>
#include <thread>
#include <string>
#include <queue>
#include <unordered_map>
using namespace std;

/* Declaring Tree node */
struct treeNode
{
	char ch;
	int freq;
	treeNode *left, *right;
};

/* getNode function to allocate a new tree node */
treeNode* getNode(char ch, int freq, treeNode* left, treeNode* right)
{
	treeNode* node = new treeNode();

	node->ch = ch;
	node->freq = freq;
	node->left = left;
	node->right = right;

	return node;
}

/* Comparing characters of left and right nodes of tree */
struct comp
{
	bool operator()(treeNode* l, treeNode* r)
	{
		// Characters with lowest frequency
		return l->freq > r->freq;
	}
};

/* After Calculating the frequencies of the characters, weights are calculated and 
*  values are assigned to left and right side of the huffman tree from root node.
*/
void encodeTree(treeNode* rootNode, string str,
	unordered_map<char, string> &huffmanCode)
{
	if (rootNode == nullptr)
		return;

	// found a leaf node
	if (!rootNode->left && !rootNode->right) {
		huffmanCode[rootNode->ch] = str;
	}
	/* Assign 0' to leftside of the root node and 1's to rightside of the root node */
	encodeTree(rootNode->left, str + "0", huffmanCode);
	encodeTree(rootNode->right, str + "1", huffmanCode);
}

/* Frequencies of characters are calculated.
 * Based on weights they are separated */
void buildHuffmanTree(string text)
{
	/* Count frequency of appearance of each character
	* and store it in a map
	*/
	unordered_map<char, int> freq;
	for (char ch : text) {
		freq[ch]++;
	}

	priority_queue<treeNode*, vector<treeNode*>, comp> pq;

	for (auto pair : freq) {
		pq.push(getNode(pair.first, pair.second, nullptr, nullptr));
	}


	while (pq.size() != 1)
	{
		treeNode *left = pq.top(); pq.pop();
		treeNode *right = pq.top();    pq.pop();

		int sum = left->freq + right->freq;
		pq.push(getNode('\0', sum, left, right));
	}

	treeNode* rootNode = pq.top();

	unordered_map<char, string> huffmanCode;
	encodeTree(rootNode, "", huffmanCode); // after assigning 0's and 1's 

	cout << "Huffman Codes of each character :\n" << '\n';
	for (auto pair : huffmanCode) {
		cout << pair.first << " " << pair.second << '\n';
	}

	cout << "\nOriginal message string is :\n" << text << '\n';
	string str = "";
	for (char ch : text) {
		str += huffmanCode[ch];
	}

	/*write the string into output text tile*/
	ofstream outfile;
	outfile.open("Huffman_Codes.txt", ios::out);
	outfile << str;
	cout << "\nHuffman Compressed Codes of original string:\n" << str << '\n';
}