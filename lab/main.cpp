#include <iostream>
#include <fstream>
#include "vigener.h"

using namespace std;

int main(int argc, char *argv[])
{
	string msg, key, alphabet;
	string fName = "in.txt";
	string kfName = "key.txt";
	string resFName = "out.txt";
	string afName;

	char mode;
	if (argc == 1)
	{
		cout << "Decode/encode/analyze(d/e/a)?" << endl;
		cin >> mode;
		if (mode != 'e' && mode != 'd' && mode != 'a')
		{
			cerr << "Wrong mode" << endl;
			return -1;
		}
		cout << "Alphabet file: ";
		cin >> afName;
		cout << "Enter file to ";
		cout << ((mode == 'e') ? "encode: " : "decode: ");
		cin >> fName;
		if (mode != 'a')
		{
			cout << "\nEnter key file: ";
			cin >> kfName;
		}
		cout << "\nEnter output file name: ";
		cin >> resFName;
	}
	else if (argc != 5 && argc != 6)
	{
		cerr << "Wrong arguments num" << endl;
		cout << "Usage: \nlab.exe mode(d/e/a) alphabet_file input_file key_file output_file\n";
		return -2;
	}
	else
	{
		mode = argv[1][0];
		if (mode != 'e' && mode != 'd' && mode != 'a')
		{
			cerr << "Wrong mode" << endl;
			return -1;
		}
		else if (mode == 'a' && argc != 5 || argc != 6)
		{
			cerr << "Wrong arguments num" << endl;
			return -2;
		}
		afName = argv[2];
		fName = argv[3];
		if (mode != 'a')
		{
			kfName = argv[4];
			resFName = argv[5];
		}
		else
			resFName = argv[4];
	}

	ifstream ifs(afName);
	ifs >> alphabet;
	ifs.close();
	Vigener cipher(alphabet);
	ifs.open(fName);
	ifs >> msg;
	ifs.close();
	if (mode != 'a')
	{
		ifs.open(kfName);
		ifs >> key;
		ifs.close();
	}
	ofstream ofs(resFName);
	if (mode != 'a')
	{
		string s = (mode == 'e') ? cipher.Encode(msg, key) : cipher.Decode(msg, key);
		ofs << s;
	}
	if (mode == 'a')
		ofs << KasiskiAnalysis(msg);
	return 0;
}