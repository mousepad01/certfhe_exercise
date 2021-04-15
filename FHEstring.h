#ifndef FHESTRING
#define FHESTRING

#include <iostream>
#include <vector>
#include <string>
#include "certFHE.h"

using namespace certFHE;

// o clasa care manipuleaza string uri in format criptat
// (momentan) un caracter este considerat ca fiind ASCII
// 
// operatiile sunt tipice string urilor:
// de concatenare, stergere, modificare a unui caracter cu altul criptat etc
class FHEstring {

private:

	Ciphertext c;		// va reprezenta string ul, impartit in bucati de lungimi de cate 7 biti criptati

	int size;	// lungimea in caractere

public:

	static const char CHAR_BIT_LEN = 7;

	// ------------- CONSTRUCTORI & DESTRUCTORI ----------------

	FHEstring() {}

	FHEstring(const char * toConvert, int toConvertLen, SecretKey & sk, Context & ct);

	FHEstring(std::string toConvert, SecretKey & sk, Context & ct);

	// nu este necesar, l-am scris pentru claritate
	FHEstring(const FHEstring & toCopy);

	~FHEstring();

	// ------------- METODE PUBLICE ----------------

	int getSize();

	std::string & decrypt(SecretKey & sk) const;

	char * decryptToChar(SecretKey & sk) const;

	void permuteKey(const Permutation & perm);

	FHEstring & getPermutedCopy(const Permutation & perm);

	// ------------- OVERLOAD OPERATORI ----------------

	// nu este necesar, l-am scris pentru claritate
	FHEstring & operator = (const FHEstring & toCopy);

	FHEstring & operator += (const FHEstring & toAdd);

	FHEstring & operator + (const FHEstring & snd) const;

	// creeaza o noua copie de lungime = 1 caracter
	FHEstring & operator [] (int pos) const;

	// returneaza un slice 
	FHEstring & operator [] (std::pair<int, int> pos) const;

	// ------------- FUNCTII FRIEND ----------------

	friend FHEstring & getConcat(const FHEstring & fst, const FHEstring & snd);

	friend FHEstring & getSlice(const FHEstring & toClip, int fstPos, int sndPos);
};

#endif
