#include "cipher.h"

Cipher::MODE convert(const char* str)
{
	if (strcmp(str, "ECB") == 0)
		return Cipher::ECB;
	else if (strcmp(str, "CBC") == 0)
		return Cipher::CBC;
	else if (strcmp(str, "CFB") == 0)
		return Cipher::CFB;
	else if (strcmp(str, "OFB") == 0)
		return Cipher::OFB;
	
	throw std::exception("Incorrect mode!");
}

void cmdParse(int argc, char **argv, Cipher *cipher)
{
	int len;
	BYTE iv[512];
	BYTE buf[512];
	BYTE res[512];
	if (argc == 4)
	{
		if (strcmp(argv[1], "gen_iv") != 0)
			std::cerr << "Incorrect mode\n";
		len = atoi(argv[2]);
		std::ofstream ofs(argv[3]);
		if (!ofs)
			std::cerr << "Incorrect file name\n";

		HCRYPTPROV hProv;

		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, 0))
		{
			std::cerr << ("Crypto lib init fail\n");
			return;
		}
		if (!CryptGenRandom(hProv, len, iv))
		{
			std::cerr << ("random IV gen fail\n");
			return;
		}
		ofs.write((const char *)iv, len);

		ofs.close();
	}
	else if (argc == 7 || argc == 6)
	{
		std::ifstream ifs;
		std::ofstream ofs;
		Cipher::MODE mode;

		mode = convert(argv[2]);
		char m = argv[1][0];
		if (mode != Cipher::ECB && argc != 7 && (m != 'e' || m != 'd'))
		{
			std::cerr << "Incorrect arg values\n"
				<< "Usage: %PROG_NAME% e/d %MODE% %key_file% %text_file% %res_file% %iv_file%\n"
				<< "or %PROG_NAME% gen_iv %length% %iv_file%";
			return;
		}
		std::string key;
		ifs.open(argv[3], std::ios::binary);
		if (!ifs)
		{
			std::cerr << "Incorrect key file name\n";
			return;
		}
		ifs >> key;
		ifs.close();
		if (!cipher->SetKey((BYTE *)key.c_str(), key.length()))
		{
			std::cerr << "Incorrect cipher key param";
			return;
		}
		if (argc == 7)
		{
			//setting iv
			ifs.open(argv[6], std::ios::binary);
			if (!ifs)
			{
				std::cerr << "Incorrect iv file name\n";
				return;
			}
			ifs.read((char *)iv, cipher->GetBlockByteLength());
			ifs.close();
		}
		//open text file and result file
		ifs.open(argv[4], std::ios::binary);
		if (!ifs)
		{
			std::cerr << "Incorrect input file name\n";
			return;
		}
		ofs.open(argv[5], std::ios::binary);
		if (!ofs)
		{
			std::cerr << "Incorrect output file name\n";
			return;
		}
		unsigned tmp;
		BYTE *_iv = iv;
		while (ifs.good())
		{
			ifs.read((char *)buf, cipher->GetBlockByteLength() * READ_AMOUNT);
			const unsigned& num = ifs.gcount();
			ifs.peek();
			if (m == 'e')
			{
				tmp = cipher->Encrypt(buf, num, mode, res, _iv, ifs.eof());
				ofs.write((char *)res, tmp);
			}
			else
			{
				tmp = cipher->Decrypt(buf, num, mode, res, _iv, ifs.eof());
				ofs.write((char *)res, tmp);
			}
			_iv = nullptr;
		}
		ofs.close();

	}
	else
	{
		std::cerr << "Incorrect arg num\n"
			<< "Usage: %PROG_NAME% e/d %MODE% %key_file% %text_file% %res_file% %iv_file%\n"
			<< "or %PROG_NAME% gen_iv %length% %iv_file%";
	}
}