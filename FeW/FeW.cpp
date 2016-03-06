#include "FeW.h"

const BYTE S[] = {
	0x2, 0xE, 0xF, 0x5, 0xC, 0x1, 0x9, 0xA,
	0xB, 0x4, 0x6, 0x8, 0x0, 0x7, 0x3, 0xD
};

DWORD FeW::_getSubKey(const BYTE& j, BYTE *key)
{
	const unsigned short& keyLen = _keyBitLength / BITS_IN_BYTE;
	short i;
	const unsigned short& usedLength = 10;
	{
		//need to shift buffer by 13 positions
		BYTE tmp = key[0];
		//shift by 8 positions - single byte
		memmove(key, key + 1, keyLen - 1);
		key[keyLen - 1] = tmp;
	}
	//shift by 5 positions
	unsigned short curShift = 5;
	BYTE prevVal = 0, nextVal;
	for (i = keyLen - 1; i >= 0; --i)
	{
		nextVal = key[i] >> (BITS_IN_BYTE - curShift);
		key[i] = (key[i] << curShift) | prevVal;
		prevVal = nextVal;
	}
	key[keyLen - 1] |= prevVal;

	//Some permutations with 4-bits key register blocks
	key[0] = (S[(key[0] >> 4)] << 4) | (key[0] & 0x0F);
	if (keyLen != usedLength)
		key[0] = (key[0] & 0xF0) | S[key[0] & 0x0F];
	key[usedLength - 1] = (key[usedLength - 1] & 0xF0) | S[key[usedLength - 1] & 0x0F];
	key[usedLength - 2] = (S[key[usedLength - 2] >> 4] << 4) | (key[usedLength - 2] & 0x0F);

	key[usedLength - 1] = (((key[usedLength - 1] >> 4) ^ (j & 0x0F)) << 4) | (key[usedLength - 1] & 0x0F);
	key[usedLength - 2] = (key[usedLength - 2] & 0xF0) | ((key[usedLength - 2] & 0x0F) ^ (j >> 4));

	return (DWORD(key[0]) << BITS_IN_BYTE) | DWORD(key[1]);
}

bool FeW::SetKey(BYTE *key, const unsigned &keyLength)
{
	if (keyLength != 10 && keyLength != 16)
		return false;

	_keyBitLength = keyLength * BITS_IN_BYTE;
	BYTE keyBuf[128];

	memcpy(keyBuf, key, keyLength);
	for (unsigned short i = 0; i < NUM_OF_ROUNDS; ++i)
		K[i] = ((_getSubKey(2 * i, keyBuf) << BITS_IN_WORD) | _getSubKey(2 * i + 1, keyBuf));

	return true;
}

inline DWORD _wf1(const WORD& x)
{
	WORD res = (WORD(S[(x >> 12) & 0xF]) << 12)
		| (WORD(S[(x >> 8) & 0xF]) << 8)
		| (WORD(S[(x >> 4) & 0xF]) << 4)
		| WORD(S[x & 0xF]);

	return (res ^ ROL(res, 1) ^ ROL(res, 5)
		^ ROL(res, 9) ^ ROL(res, 12));
}
inline DWORD _wf2(const WORD& x)
{
	WORD res = (WORD(S[(x >> 12) & 0xF]) << 12)
		| (WORD(S[(x >> 8) & 0xF]) << 8)
		| (WORD(S[(x >> 4) & 0xF]) << 4)
		| WORD(S[x & 0xF]);

	return (res ^ ROL(res, 4) ^ ROL(res, 7)
		^ ROL(res, 11) ^ ROL(res, 15));
}

DWORD FeW::_f(const DWORD& P, const unsigned short& i)
{
	DWORD tmp;
	tmp = P ^ K[i];

	return (_wf1((getByteFromDWORD(tmp, 3) << BITS_IN_BYTE) | getByteFromDWORD(tmp, 0))
		<< (BITS_IN_DWORD / 2))
		| _wf2((getByteFromDWORD(tmp, 1) << BITS_IN_BYTE) | getByteFromDWORD(tmp, 2));
}

void FeW::_encryptBlock(const BYTE *msg, BYTE *res)
{
	short i, j;
	DWORD tmp;
	P[0] = 0, P[1] = 0;

	for (i = 0; i < BLOCK_BYTE_LENGTH / BYTES_IN_DWORD; ++i)
		for (j = 0; j < BYTES_IN_DWORD; ++j)
			P[i] += (DWORD(msg[4 * i + j]) << (8 * j));

	for (i = 0; i < NUM_OF_ROUNDS; ++i)
	{
		tmp = P[0] ^ _f(P[1], i);
		P[0] = P[1];
		P[1] = tmp;
	}
	std::swap(P[0], P[1]);

	for (i = 0; i < BLOCK_BYTE_LENGTH; ++i)
		res[i] = BYTE(P[i / 4] >> (8 * (i & REM_DWORD_BYTE_SIZE)));
}

void FeW::_decryptBlock(const BYTE *msg, BYTE *res)
{
	short i, j;
	DWORD tmp;
	P[0] = 0, P[1] = 0;

	for (i = 0; i < BLOCK_BYTE_LENGTH / BYTES_IN_DWORD; ++i)
		for (j = 0; j < BYTES_IN_DWORD; ++j)
			P[i] += (DWORD(msg[4 * i + j]) << (8 * j));

	for (i = NUM_OF_ROUNDS - 1; i >= 0; --i)
	{
		tmp = P[0] ^ _f(P[1], i);
		P[0] = P[1];
		P[1] = tmp;
	}
	std::swap(P[0], P[1]);

	for (i = 0; i < BLOCK_BYTE_LENGTH; ++i)
		res[i] = BYTE(P[i / 4] >> (8 * (i & REM_DWORD_BYTE_SIZE)));
}