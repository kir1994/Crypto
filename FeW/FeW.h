#include "../Cipher/cipher.h"

const short BLOCK_BYTE_SIZE = 8;
const short NUM_OF_ROUNDS = 32;

/* Implementation of lightweight FeW cipher 
 * 
 * Cipher authors: Manoj Kumar, Saibal K. Pal and Anupama Panigrahi
 * Paper: https://eprint.iacr.org/2014/326.pdf
 */

class FeW : public Cipher
{
	DWORD P[2];
	DWORD K[NUM_OF_ROUNDS];
	WORD rf1, rf2;

	DWORD _f(const DWORD& P, const unsigned short& i);

	virtual void _encryptBlock(const BYTE *msg, BYTE *res);
	virtual void _decryptBlock(const BYTE *msg, BYTE *res);
	DWORD _getSubKey(const BYTE& j, BYTE *key);

public:
	virtual bool SetKey(BYTE *key, const unsigned &keyLength);
	
	FeW() : Cipher(BLOCK_BYTE_SIZE) {}

};