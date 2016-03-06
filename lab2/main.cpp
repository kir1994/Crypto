#include "twofish.h"

using namespace std;

int main(int argc, char **argv)
{	
	Twofish tf;

	cmdParse(argc, argv, &tf);
	/*string s = "abcdabcdabcdabcd";
	string a = "dcbadcbadcbadcb";
	string word = s;
	BYTE res[500];
	BYTE key[500] = { 0 };
	tf.SetKey((unsigned char *)s.c_str(), 16);
	tf.Encrypt((unsigned char *)word.c_str(), word.length(), Cipher::ECB, res);
	tf.Decrypt(res, word.length(), Cipher::ECB, key);*/
	return 0;
}