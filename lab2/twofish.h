#include "../Cipher/cipher.h"

const short NUM_OF_ROUNDS = 16;
const short MAX_KEY_LENGTH = 256;

/* Implementation of twofish cipher (finalist of AES competition)
*
* Cipher authors: B. Schneier, J. Kelsey, D. Whiting, D. Wagner, C. Hall, and N. Ferguson
* Paper: https://www.schneier.com/cryptography/paperfiles/paper-twofish-paper.pdf
*/

class Twofish : public Cipher
{
	DWORD K[2 * BYTES_IN_DWORD + 2 * NUM_OF_ROUNDS];

	DWORD Me[MAX_KEY_LENGTH / 64];
	DWORD Mo[MAX_KEY_LENGTH / 64];

	DWORD S[MAX_KEY_LENGTH / 64];

	unsigned _keyBitLength;

	DWORD P[BYTES_IN_DWORD];
	DWORD F0, F1;
	DWORD T0, T1;	


	inline void _clear()
	{
		for (unsigned i = 0; i < BYTES_IN_DWORD; ++i)
			P[i] = 0;
	}

	DWORD _h(DWORD X, DWORD *L);

	inline BYTE getKeySym(BYTE* key, const unsigned& realLength, const unsigned& pos)
	{
		return (pos < realLength) ? key[pos] : 0;
	}

	void _generateKeys(BYTE *key, const unsigned& len);

	inline void _inputWhitening(unsigned offset = 0)
	{
		//XOR with round keys
		for (unsigned i = 0; i < BYTES_IN_DWORD; ++i)
			P[i] ^= K[i + offset];
	}
	
	inline void _outputWhitening(unsigned offset = BYTES_IN_DWORD)
	{
		//XOR with round keys
		for (unsigned i = 0; i < BYTES_IN_DWORD; ++i)
			P[(i + 2) & REM_DWORD_BYTE_SIZE] ^= K[i + offset];
		//Some swapping, 'undoing' last feistel swap
		std::swap(P[0], P[2]);
		std::swap(P[1], P[3]);
	}

	inline DWORD _g(const DWORD& R)
	{		
		return _h(R, S);
	}

	void _f(const unsigned short& r)
	{
		T0 = _g(P[0]);
		T1 = _g(ROL(P[1], 8));

		F0 = DWORD((unsigned long long)T1 + T0 + K[2 * r + 8]);
		F1 = DWORD((unsigned long long)T1 * 2 + T0 + K[2 * r + 9]);
	}

	void _feistelNet(const unsigned short& r);
	
	void  _feistelDecNet(const unsigned short& r);
	
	virtual void _encryptBlock(const BYTE *msg, BYTE *res);

	virtual void _decryptBlock(const BYTE *CT, BYTE *PT);
	
public:
	Twofish() : Cipher(BYTES_IN_DWORD * BYTES_IN_DWORD) {}

	virtual bool SetKey(BYTE *key, const unsigned &keyLength);
		
};