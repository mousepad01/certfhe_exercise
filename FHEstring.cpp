#include "FHEstring.h"

FHEstring::FHEstring(const char * toConvert, int toConvertLen, SecretKey & sk, Context & ct) {

	if (toConvertLen > 0 && toConvert != nullptr) {

		Plaintext aux;

		this -> c.setContext(ct);

		for (int chr = 0; chr < toConvertLen; chr++) {

			char auxChr = toConvert[chr];
			for (int b = 0; b < CHAR_BIT_LEN; b++) {

				aux = Plaintext(auxChr & 1);
				auxChr >>= 1;

				c += sk.encrypt(aux);
			}

			size += 1;
		}
	}

}

FHEstring::FHEstring(std::string toConvert, SecretKey & sk, Context & ct) {

	Plaintext aux;

	this -> c.setContext(ct);

	for (int chr = 0; chr < toConvert.size(); chr++) {

		char auxChr = toConvert[chr];
		for (int b = 0; b < CHAR_BIT_LEN; b++) {

			aux = Plaintext(auxChr & 1);
			auxChr >>= 1;

			c += sk.encrypt(aux);
		}

		size += 1;
	}
}

FHEstring::FHEstring(const FHEstring & toCopy) {
	std::cout << "copy\n";
	this -> c = toCopy.c;
	this -> size = toCopy.size;
}

FHEstring::~FHEstring() {
	size = 0;
}

int FHEstring::getSize() {
	return this -> size;
}

char * FHEstring::decryptToChar(SecretKey & sk) const {

	char * toReturn = new char[this -> size];

	Ciphertext aux;

	aux.setContext(this -> c.getContext());

	uint64_t defLen = this -> c.getContext().getDefaultN();

	uint64_t * v = this -> c.getValues();
	uint64_t * bl = this -> c.getBitlen();

	for (int chr = 0; chr < this -> size; chr++){
	
		toReturn[chr] = 0;
		for (int b = 0; b < CHAR_BIT_LEN; b++) {

			aux.setValues(v + (chr * CHAR_BIT_LEN + b) * defLen, defLen);
			aux.setBitlen(bl + (chr * CHAR_BIT_LEN + b) * defLen, defLen);

			toReturn[chr] |= ((sk.decrypt(aux).getValue()) << b);
		}
	}

	return toReturn;
}

std::string & FHEstring::decrypt(SecretKey & sk) const {

	char * toConvert = decryptToChar(sk);
	std::string * toReturn = new std::string(toConvert, this -> size);

	return *toReturn;
}

void FHEstring::permuteKey(const Permutation & perm) {

	if (this -> size == 0)
		return;

	this -> c.applyPermutation_inplace(perm);
}

FHEstring & FHEstring::getPermutedCopy(const Permutation & perm) {

	if (this -> size == 0)
		return *(new FHEstring);

	FHEstring * thisPermuted = new FHEstring(*this);
	thisPermuted -> permuteKey(perm);

	return *thisPermuted;
}

FHEstring & FHEstring::operator = (const FHEstring & toCopy) {
	
	this -> c = toCopy.c;
	this -> size = toCopy.size;

	return *this;
}

FHEstring & FHEstring::operator += (const FHEstring & toAdd) {

	this -> c += toAdd.c;
	this -> size += toAdd.size;

	return *this;
}

FHEstring & FHEstring::operator + (const FHEstring & toAdd) const {

	return getConcat(*this, toAdd);
}

FHEstring & FHEstring::operator [] (int pos) const {

	if (pos < 0 && pos >= -(this -> size))
		pos += this -> size;

	if (pos < 0 || pos > this -> size)
		throw out_of_range("pozitia din string nu exista");

	FHEstring * newChar = new FHEstring;

	uint64_t * v = this -> c.getValues();
	uint64_t * bl = this -> c.getBitlen();
	uint64_t defLen = this -> c.getContext().getDefaultN();

	newChar -> c.setContext(this -> c.getContext());
	newChar -> c.setValues(v + CHAR_BIT_LEN * defLen * pos, CHAR_BIT_LEN * defLen);
	newChar -> c.setBitlen(bl + CHAR_BIT_LEN * defLen * pos, CHAR_BIT_LEN * defLen);

	newChar -> size = 1;

	return *newChar;
}

FHEstring & FHEstring::operator [] (std::pair<int, int> pos) const {

	try {
		FHEstring & toReturn = getSlice(*this, pos.first, pos.second);
	}
	catch (out_of_range & err) {
		throw err;
	}
}

FHEstring & getConcat(const FHEstring & fst, const FHEstring & snd) {

	FHEstring * newStr = new FHEstring;
	
	if (fst.size == 0) 
		*newStr = fst;

	else if (snd.size == 0) 
		*newStr = snd;

	else {

		newStr -> c = fst.c + snd.c;
		newStr -> size = fst.size + snd.size;
	}

	return *newStr;
}

// intoarce slice corespunzator intervalului [fstPos, sndPos)
FHEstring & getSlice(const FHEstring & toClip, int fstPos, int sndPos) {

	if (fstPos < 0 && sndPos < 0) {

		if (fstPos >= sndPos || fstPos < -toClip.size || sndPos < -toClip.size)
			throw out_of_range("pozitiile din string nu exista sau sunt inversate");

		fstPos += toClip.size;
		sndPos += toClip.size;
	}
	else if (fstPos < 0 || sndPos < 0 || fstPos > toClip.size || sndPos > toClip.size || fstPos >= sndPos)
		throw out_of_range("pozitiile din string nu exista sau sunt inversate");
		

	FHEstring * newStr = new FHEstring;

	uint64_t * v = toClip.c.getValues();
	uint64_t * bl = toClip.c.getBitlen();
	uint64_t defLen = toClip.c.getContext().getDefaultN();

	newStr -> c.setValues(v + fstPos * FHEstring::CHAR_BIT_LEN * defLen, (sndPos - fstPos) * FHEstring::CHAR_BIT_LEN * defLen);
	newStr -> c.setBitlen(bl + fstPos * FHEstring::CHAR_BIT_LEN * defLen, (sndPos - fstPos) * FHEstring::CHAR_BIT_LEN * defLen);
	newStr -> c.setContext(toClip.c.getContext());

	newStr -> size = (sndPos - fstPos);

	return *newStr;
}

