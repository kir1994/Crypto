#include <string>
#include <map>
#include <vector>

using namespace std;

class Vigener
{
	string alphabet;
	unsigned alphabet_size;

	char _getEncodingSymbol(const char& mSym, const char& kSym)
	{
		return alphabet[((kSym - alphabet[0]) * _shift + (mSym - alphabet[0])) % alphabet_size];
	}
	char _getDecodingSymbol(const char& ctSym, const char& kSym)
	{
		return alphabet[(ctSym - alphabet[((kSym - alphabet[0]) * _shift) % alphabet_size] + alphabet_size) % alphabet_size];
	}
	unsigned _shift;

	string res;

public:
	Vigener(const string &ab, const unsigned shift = 1) : _shift(shift)
	{
		alphabet = ab;
		alphabet_size = ab.length();
	}

	string Encode(const string& msg, const string& key)
	{
		res = "";
		unsigned keyOffset = 0;
		for (unsigned i = 0; i < msg.length(); ++i)
		{
			res += _getEncodingSymbol(msg[i], key[keyOffset]);
			keyOffset++;
			if (keyOffset >= key.length())
				keyOffset = 0;
		}
		return res;
	}

	string Decode(const string& ctext, const string& key)
	{
		res = "";
		unsigned keyOffset = 0;
		for (unsigned i = 0; i < ctext.length(); ++i)
		{
			res += _getDecodingSymbol(ctext[i], key[keyOffset]);
			keyOffset++;
			if (keyOffset >= key.length())
				keyOffset = 0;
		}
		return res;
	}
};

template<class T>
T gcd(T& a, T& b)
{
	T num1(a);
	T num2(b);
	T tmp;
	if (!(a >= b))
	{
		tmp = num1;
		num1 = num2;
		num2 = tmp;
	}
	while (num2 != 0)
	{
		tmp = num1;
		num1 = num2;
		num2 = tmp % num2;
	}
	return num1;
}

unsigned KasiskiAnalysis(const string& ct)
{
	const unsigned seg_length = 3;
	string tmp;
	vector<unsigned> dists;
	size_t l, r;
	unsigned max_dist = 0;
	unsigned prev_max = 0;
	for (unsigned i = 0; i < ct.length() - 2; i++)
	{
		tmp = ct.substr(i, seg_length);
		l = i;
		r = ct.find(tmp, l + 1);
		while (r != ct.npos)
		{
			dists.push_back(r - l);
			if (r - l > max_dist)
				max_dist = r - l;
			else if (r - l > prev_max)
				prev_max = r - l;
			l = r;
			r = ct.find(tmp, l + 1);
		}
	}
	unsigned *gcds = new unsigned[prev_max + 1]();

	for (unsigned i = 0; i < dists.size(); ++i)
		for (unsigned j = i + 1; j < dists.size(); ++j)
			gcds[gcd(dists[i], dists[j])]++;
	unsigned res = 0;
	for (unsigned i = 1; i <= prev_max; ++i)
		if (gcds[res] < gcds[i])
			res = i;

	return res;
}



