#include <windows.h>
#include <intrin.h>
#include <iostream>
#include <fstream>
#include <wincrypt.h>
#include <string>

const short BITS_IN_BYTE = 8;
const short BYTE_MASK = 0xFF;
const short BITS_IN_DWORD = 32;
const short BYTES_IN_DWORD = BITS_IN_DWORD / BITS_IN_BYTE;
const short REM_DWORD_BYTE_SIZE = BYTES_IN_DWORD - 1;
const short REM_DWORD_BIT_SIZE = BITS_IN_DWORD - 1;
const short BITS_IN_WORD = 16;
const short BYTES_IN_WORD = BITS_IN_WORD / BITS_IN_BYTE;
const short REM_WORD_BYTE_SIZE = BYTES_IN_WORD - 1;
const short REM_WORD_BIT_SIZE = BITS_IN_WORD - 1;

inline void XOR(const BYTE* x, BYTE *res, const short& length)
{
	for (short i = 0; i < length; ++i)
		res[i] ^= x[i];
}

inline BYTE getByteFromDWORD(const DWORD& num, const short& pos)
{
	return (num >> ((pos & REM_DWORD_BYTE_SIZE) * BITS_IN_BYTE)) & BYTE_MASK;
}

inline DWORD ROL(const DWORD& x, const unsigned char& n)
{
	return _lrotl(x, n);
}

inline DWORD ROR(const DWORD& x, const unsigned char& n)
{
	return _lrotr(x, n);
}

inline WORD ROL(const WORD& x, const unsigned char& n)
{
	return _rotl16(x, n);
}

inline WORD ROR(const WORD& x, const unsigned char& n)
{
	return _rotr16(x, n);
}

class Cipher
{
protected:
	unsigned _keyBitLength;
	unsigned short BLOCK_BYTE_LENGTH;

	BYTE *buffer;
	BYTE *fb_buf;

	virtual void _encryptBlock(const BYTE *msg, BYTE *res) = 0;
	virtual void _decryptBlock(const BYTE *msg, BYTE *res) = 0;

public:
	enum MODE{ ECB, CBC, CFB, OFB };

	Cipher(const unsigned short& blkLen) : BLOCK_BYTE_LENGTH(blkLen)
	{
		buffer = new BYTE[blkLen];
		fb_buf = new BYTE[blkLen];
	}

	~Cipher()
	{
		delete[] buffer;
		delete[] fb_buf;
	}

	virtual bool SetKey(BYTE *key, const unsigned &keyLength) = 0;

	unsigned short GetBlockByteLength() const
	{
		return BLOCK_BYTE_LENGTH;
	}

	unsigned Encrypt(const BYTE *msg, const unsigned& length, const MODE& mode, BYTE *res, BYTE *IV = nullptr, bool useDummy = false)
	{
		const unsigned& tmp = length / BLOCK_BYTE_LENGTH;
		const unsigned& rem = length % BLOCK_BYTE_LENGTH;
		unsigned i;

		switch (mode)
		{
		case ECB://electronic codebook
			for (i = 0; i < tmp; ++i)
				_encryptBlock(msg + i * BLOCK_BYTE_LENGTH, res + i * BLOCK_BYTE_LENGTH);
			if (useDummy)
			{
				for (i = rem; i < BLOCK_BYTE_LENGTH; ++i)
					buffer[i] = BLOCK_BYTE_LENGTH - rem;
				memcpy(buffer, msg + tmp * BLOCK_BYTE_LENGTH, rem);
				_encryptBlock(buffer, res + tmp * BLOCK_BYTE_LENGTH);
				if (rem == 0)
					return (tmp + 1) * BLOCK_BYTE_LENGTH;
			}
			break;
		case CBC://cipher-block chaining
			if (IV != nullptr)
				memcpy(buffer, IV, BLOCK_BYTE_LENGTH * sizeof(BYTE));
			for (i = 0; i < tmp; ++i)
			{
				XOR(msg + i * BLOCK_BYTE_LENGTH, buffer, BLOCK_BYTE_LENGTH);
				_encryptBlock(buffer, res + i * BLOCK_BYTE_LENGTH);
				memcpy(buffer, res + i * BLOCK_BYTE_LENGTH, BLOCK_BYTE_LENGTH * sizeof(BYTE));
			}
			if (useDummy)
			{
				XOR(msg + tmp * BLOCK_BYTE_LENGTH, buffer, rem);
				for (i = rem; i < BLOCK_BYTE_LENGTH; ++i)
					buffer[i] ^= BYTE(BLOCK_BYTE_LENGTH - rem);
				_encryptBlock(buffer, res + tmp * BLOCK_BYTE_LENGTH);
				if (rem == 0)
					return (tmp + 1) * BLOCK_BYTE_LENGTH;
			}
			break;
		case CFB://cipher feedback
			//r = 8. r - Shift register capacity
			if (IV != nullptr)
				memcpy(buffer, IV, sizeof(BYTE)* BLOCK_BYTE_LENGTH);
			for (i = 0; i < length; ++i)
			{
				_encryptBlock(buffer, fb_buf);
				res[i] = fb_buf[0] ^ msg[i];
				memmove(buffer, buffer + 1, sizeof(BYTE)* (BLOCK_BYTE_LENGTH - 1));
				buffer[BLOCK_BYTE_LENGTH - 1] = res[i];
			}
			return length;
			break;
		case OFB://output feedback
			// per ISO 10116
			// r = 8. r - Shift register capacity
			if (IV != nullptr)
				memcpy(buffer, IV, sizeof(BYTE)* BLOCK_BYTE_LENGTH);
			for (i = 0; i < length; ++i)
			{
				_encryptBlock(buffer, buffer);
				res[i] = buffer[0] ^ msg[i];
			}
			return length;
			break;
		}
		return (length + (BLOCK_BYTE_LENGTH - 1)) / BLOCK_BYTE_LENGTH * BLOCK_BYTE_LENGTH;
	}

	int Decrypt(const BYTE *msg, const unsigned& length, const MODE& mode, BYTE *res, BYTE *IV = nullptr, bool useDummy = false)
	{
		const unsigned& tmp = length / BLOCK_BYTE_LENGTH; 
		unsigned val;
		unsigned i;

		switch (mode)
		{
		case ECB://electronic codebook
			if (!useDummy)
			{
				for (i = 0; i < tmp; ++i)
					_decryptBlock(msg + i * BLOCK_BYTE_LENGTH, res + i * BLOCK_BYTE_LENGTH);
			}
			else
			{
				for (i = 0; i < tmp - 1; ++i)
					_decryptBlock(msg + i * BLOCK_BYTE_LENGTH, res + i * BLOCK_BYTE_LENGTH);

				_decryptBlock(msg + (tmp - 1) * BLOCK_BYTE_LENGTH, buffer);
				val = buffer[BLOCK_BYTE_LENGTH - 1];
				memcpy(buffer, res + (tmp - 1) * BLOCK_BYTE_LENGTH, BLOCK_BYTE_LENGTH - val);

				return ((tmp - 1) * BLOCK_BYTE_LENGTH + (BLOCK_BYTE_LENGTH - val));
			}
			break;
		case CBC://cipher-block chaining
			if (IV != nullptr)
				memcpy(buffer, IV, BLOCK_BYTE_LENGTH * sizeof(BYTE));
			if (useDummy)
			{
				for (i = 0; i < (tmp - 1); ++i)
				{
					_decryptBlock(msg + i * BLOCK_BYTE_LENGTH, res + i * BLOCK_BYTE_LENGTH);
					XOR(buffer, res + i * BLOCK_BYTE_LENGTH, BLOCK_BYTE_LENGTH);
					memcpy(buffer, msg + i * BLOCK_BYTE_LENGTH, BLOCK_BYTE_LENGTH * sizeof(BYTE));
				}
				_decryptBlock(msg + (tmp - 1) * BLOCK_BYTE_LENGTH, fb_buf/*res + tmp * BLOCK_BYTE_LENGTH*/);
				val = buffer[BLOCK_BYTE_LENGTH - 1] ^ fb_buf[BLOCK_BYTE_LENGTH - 1];
				for (i = 0; i < BLOCK_BYTE_LENGTH - val; ++i)
					(res + (tmp - 1) * BLOCK_BYTE_LENGTH)[i] = buffer[i] ^ fb_buf[i];

				return ((tmp - 1) * BLOCK_BYTE_LENGTH + (BLOCK_BYTE_LENGTH - val));
			}
			else
			{
				for (i = 0; i < tmp; ++i)
				{
					_decryptBlock(msg + i * BLOCK_BYTE_LENGTH, res + i * BLOCK_BYTE_LENGTH);
					XOR(buffer, res + i * BLOCK_BYTE_LENGTH, BLOCK_BYTE_LENGTH);
					memcpy(buffer, msg + i * BLOCK_BYTE_LENGTH, BLOCK_BYTE_LENGTH * sizeof(BYTE));
				}
			}
			//XOR(buffer, res + tmp * BLOCK_BYTE_LENGTH, val);
			break;
		case CFB://cipher feedback
			//r = 8;
			if (IV != nullptr)
				memcpy(buffer, IV, sizeof(BYTE)* BLOCK_BYTE_LENGTH);
			for (i = 0; i < length; ++i)
			{
				_encryptBlock(buffer, fb_buf);
				res[i] = fb_buf[0] ^ msg[i];
				memmove(buffer, buffer + 1, sizeof(BYTE)* (BLOCK_BYTE_LENGTH - 1));
				buffer[BLOCK_BYTE_LENGTH - 1] = msg[i];
			}			
			break;
		case OFB://output feedback
			// per ISO 10116
			// r = 8. r - Shift register capacity
			if (IV != nullptr)
				memcpy(buffer, IV, sizeof(BYTE)* BLOCK_BYTE_LENGTH);
			for (i = 0; i < length; ++i)
			{
				_encryptBlock(buffer, buffer);
				res[i] = buffer[0] ^ msg[i];
			}
			break;
		}
		return length;
	}

};



const unsigned short READ_AMOUNT = 1;

Cipher::MODE convert(const char* str);
void cmdParse(int argc, char **argv, Cipher *cipher);