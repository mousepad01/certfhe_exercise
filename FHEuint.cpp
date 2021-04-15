#include "FHEuint.h"
#include <fstream>

uint64_t FHEuint::decrypt(uint64_t* v, uint64_t len, uint64_t defLen, uint64_t n, uint64_t d, uint64_t* s, uint64_t* bitlen, uint64_t * carry) {

	int totalLen = 0;
	for (int i = 0; i < len; i++)
		totalLen = totalLen + bitlen[i];
	uint8_t *values = new uint8_t[totalLen];

	int index = 0;
	for (int i = 0; i < len; i++)
		for (int k = 0; k < bitlen[i]; k++)
		{
			int shifts = sizeof(uint64_t) * 8 - 1 - k;
			values[index] = (v[i] >> shifts) & 0x01;

			index++;

		}

	uint64_t times = len / defLen;

	uint64_t dec = values[s[0]];
	uint64_t _dec = 0;

	for (int k = 0; k < times; k++)
	{
		dec = values[n*k + s[0]];
		for (int i = 1; i < d; i++)
		{
			dec = dec & values[n*k + s[i]];
		}

		//----
		if (_dec == 1 && dec == 1)
			*carry += 1;
		//----

		_dec = (dec + _dec) % 2;
	}

	dec = _dec;

	delete[] values;

	return dec;
}

FHEuint::FHEuint(const FHEuint & toCopy) {

	this -> c = toCopy.c;
	this -> digitLen = toCopy.digitLen;
}

FHEuint::FHEuint(uint64_t toConvert, SecretKey & sk, Context & ct) {

	Plaintext aux(toConvert & 1);
	this -> c = sk.encrypt(aux); // la atribuire nu se copiaza si contextul, trb sa fac asta manual
	this -> c.setContext(ct);

	toConvert >>= 1;
	this->digitLen.push_back(1);

	while (toConvert) {

		aux = Plaintext(toConvert & 1);
		this->c += sk.encrypt(aux);

		toConvert >>= 1;
		this->digitLen.push_back(1);
	}
}

FHEuint::~FHEuint() {
	for (int i = 0; i < this -> digitLen.size(); i++)
		digitLen[i] = 0;
}

int FHEuint::getDigitsCnt() {
	return this -> digitLen.size();
}

uint64_t FHEuint::decrypt(SecretKey & sk) {

	if (this -> digitLen.empty())
		throw invalid_argument("FHEuint neinitializat");

	// variabile auxiliare

	uint64_t toReturn = 0;

	uint64_t decryptedDigit;

	Plaintext auxPlain;
	Ciphertext aux;
	aux.setContext(this -> c.getContext());

	uint64_t * v = this -> c.getValues();
	uint64_t * bl = this -> c.getBitlen();

	uint64_t offset = 0;
	uint64_t defLen = this -> c.getContext().getDefaultN();

	uint64_t currentDigitLen = 0;

	// decriptare

	for (int digit = 0; digit < this -> digitLen.size(); digit++) {

		currentDigitLen = digitLen[digit] * defLen;

		if (currentDigitLen == defLen) {

			aux.setValues(v + offset, currentDigitLen);
			aux.setBitlen(bl + offset, currentDigitLen);

			auxPlain = sk.decrypt(aux);
			//std::cout << "toret " << toReturn << " ";
			//std::cout << "digit " << digit << " value " << (int)auxPlain.getValue() << '\n';

			if ((int)auxPlain.getValue() == 1)
				toReturn += (1 << digit);
		}
		else {

			uint64_t carry = 0;

			decryptedDigit = this -> decrypt(v + offset, currentDigitLen, defLen, this -> c.getContext().getN(), this -> c.getContext().getD(), sk.getKey(), bl + offset, &carry);

			toReturn += (carry << (digit + 1));
			toReturn += (decryptedDigit << digit);
			//std::cout << "toret " << toReturn << " ";
			//std::cout << "digit " << digit << " value " << decryptedDigit << " carry " << carry << '\n';
		}

		offset += currentDigitLen;
	}

	return toReturn;
}

void FHEuint::permuteKey(const Permutation & p) {

	if (this -> digitLen.empty())
		return;

	this -> c.applyPermutation_inplace(p);
}

FHEuint & FHEuint::getPermutedCopy(const Permutation & p) {

	if (this -> digitLen.empty())
		return *(new FHEuint); 

	FHEuint * thisPermuted = new FHEuint(*this);
	thisPermuted -> permuteKey(p);

	return *thisPermuted;
}

void FHEuint::showDigits(SecretKey & sk) const {

	if (this -> digitLen.empty()) {

		std::cout << "FHEuint neinitializat";
		return;
	}

	int offset = 0;

	uint64_t * v = this -> c.getValues();
	uint64_t * bl = this -> c.getBitlen();

	uint64_t defLen = this -> c.getContext().getDefaultN();

	for (int digit = 0; digit < this -> digitLen.size(); digit++) {

		std::cout << "digit " << digit << ", " << digitLen[digit] << " chunks:\n";

		for (int i = 0; i < digitLen[digit]; i++) {

			Ciphertext ca;
			ca.setContext(this -> c.getContext());
			ca.setValues(v + (offset + i) * defLen, defLen);
			ca.setBitlen(bl + (offset + i) * defLen, defLen);

			std::cout << sk.decrypt(ca) << " ";
		}
		std::cout << '\n';

		offset += digitLen[digit];
	}
}

FHEuint & FHEuint::operator * (const FHEuint & snd) const {

	if (this -> digitLen.empty())
		throw invalid_argument("primul FHEuint este neinitializat");

	if (snd.digitLen.empty())
		throw invalid_argument("al doilea FHEuint este neinitializat");

	FHEuint & rez = multiply(*this, snd);
	return rez;
}

FHEuint & FHEuint::operator = (const FHEuint & toCopy) {

	/*this -> c.setValues(toCopy.c.getValues(), toCopy.c.getLen());
	this -> c.setBitlen(toCopy.c.getBitlen(), toCopy.c.getLen());
	this -> c.setContext(toCopy.c.getContext());*/

	this -> c = toCopy.c;
	this -> digitLen = toCopy.digitLen;

	return *this;
}

/* consumul de memorie s-ar putea optimiza */
FHEuint & FHEuint::operator *= (const FHEuint & snd) {

	if (this -> digitLen.empty())
		throw invalid_argument("primul FHEuint este neinitializat");

	if (snd.digitLen.empty())
		throw invalid_argument("al doilea FHEuint este neinitializat");

	FHEuint & rez = multiply(*this, snd);

	this -> c = rez.c;
	this -> digitLen = rez.digitLen;

	delete &rez;

	return *this;
}

FHEuint & FHEuint::operator + (const FHEuint & snd) const {

	if (this -> digitLen.empty())
		throw invalid_argument("primul FHEuint este neinitializat");

	if (snd.digitLen.empty())
		throw invalid_argument("al doilea FHEuint este neinitializat");

	FHEuint & rez = add(*this, snd);
	return rez;
}

/* consumul de memorie s-ar putea optimiza */
FHEuint & FHEuint::operator += (const FHEuint & snd) {

	if (this -> digitLen.empty())
		throw invalid_argument("primul FHEuint este neinitializat");

	if (snd.digitLen.empty())
		throw invalid_argument("al doilea FHEuint este neinitializat");

	FHEuint & rez = add(*this, snd);

	this -> c = rez.c;
	this -> digitLen = rez.digitLen;

	delete &rez;

	return *this;
}

FHEuint & multiply(const FHEuint & fst, const FHEuint & snd) {

	if (fst.digitLen.empty())
		throw invalid_argument("primul FHEuint este neinitializat");

	if (snd.digitLen.empty())
		throw invalid_argument("al doilea FHEuint este neinitializat");

	// initializari de vaariabile auxiliare

	FHEuint * rez = new FHEuint;				// rezultatul inmultirii
	rez -> c.setContext(fst.c.getContext());

	uint64_t * fstv = fst.c.getValues();		// ciphertext ul primului nr
	uint64_t * sndv = snd.c.getValues();		// ciphertext ul celui de al doilea nr

	uint64_t * fstbl = fst.c.getBitlen();	// bitlen corespunzator primului nr
	uint64_t * sndbl = snd.c.getBitlen();	// bitlen corespunzator celui de al doiela nr

	std::vector<int> fstDigitLenPartialSum(fst.digitLen.size());
	std::vector<int> sndDigitLenPartialSum(snd.digitLen.size());

	Ciphertext fstaux, sndaux;	// ciphertext uri auxiliare folosite in inmultire
	fstaux.setContext(fst.c.getContext());
	sndaux.setContext(snd.c.getContext());

	uint64_t defLen = fst.c.getContext().getDefaultN();	// dimensiunea unui chunk de ciphertext

	// preprocesari

	// am nevoie de pozitia in ciphertext a fiecarei cifre in baza 2
	// DigitLen furnizeaza numai lungimea fiecarei cifre 
	// DigitLenPartialSum furnizeaza pozitia de inceput a fiecarei cifre
	// (pozitie exprimata in nr de chunks de lungime defLen de la inceputul chiphertextului)

	fstDigitLenPartialSum[0] = 0;
	for (int i = 1; i < fstDigitLenPartialSum.size(); i++)
		fstDigitLenPartialSum[i] = fstDigitLenPartialSum[i - 1] + (fst.digitLen[i - 1]);

	sndDigitLenPartialSum[0] = 0;
	for (int i = 1; i < sndDigitLenPartialSum.size(); i++)
		sndDigitLenPartialSum[i] = sndDigitLenPartialSum[i - 1] + (snd.digitLen[i - 1]);

	// realizarea inmultirii
	// for urile sunt plasate a.i. adunarea produselor intermediare sa necesite 
	//                             cat mai putine structuri auxiliare

	int n = fstDigitLenPartialSum.size();
	int m = sndDigitLenPartialSum.size();

	for (int rezDigit = 0; rezDigit < m + n; rezDigit++) {

		for (int fstDigit = max(0, rezDigit - m - 1); fstDigit <= min(n - 1, rezDigit); fstDigit++)
			for (int sndDigit = min(m - 1, rezDigit); sndDigit >= max(0, rezDigit - n - 1); sndDigit--)

				if (fstDigit + sndDigit == rezDigit) {

					for (int i = 0; i < fst.digitLen[fstDigit]; i++) {
						for (int j = 0; j < snd.digitLen[sndDigit]; j++) {

							int offsetFst = fstDigitLenPartialSum[fstDigit] + i;
							int offsetSnd = sndDigitLenPartialSum[sndDigit] + j;

							fstaux.setValues(fstv + offsetFst * defLen, defLen);
							fstaux.setBitlen(fstbl + offsetFst * defLen, defLen);

							sndaux.setValues(sndv + offsetSnd * defLen, defLen);
							sndaux.setBitlen(sndbl + offsetSnd * defLen, defLen);

							fstaux *= sndaux;

							rez -> c += fstaux;

							if (rezDigit >= rez -> digitLen.size())
								rez -> digitLen.push_back(1);
							else
								rez -> digitLen[rezDigit] += 1;
						}
					}
				}

	}

	return *rez;
}

FHEuint & add(const FHEuint & fst, const FHEuint & snd) {

	if (fst.digitLen.empty())
		throw invalid_argument("primul FHEuint este neinitializat");

	if (snd.digitLen.empty())
		throw invalid_argument("al doilea FHEuint este neinitializat");

	FHEuint * rez = new FHEuint();				// rezultatul adunarii
	rez -> c.setContext(fst.c.getContext());

	uint64_t * fstv = fst.c.getValues();		// ciphertext ul primului nr
	uint64_t * sndv = snd.c.getValues();		// ciphertext ul celui de al doilea nr

	uint64_t * fstbl = fst.c.getBitlen();	// bitlen corespunzator primului nr
	uint64_t * sndbl = snd.c.getBitlen();	// bitlen corespunzator celui de al doiela nr

	int fstDlen = fst.digitLen.size();
	int sndDlen = snd.digitLen.size();

	rez -> digitLen = std::vector<int>(max(fstDlen, sndDlen));

	int offsetFst = 0;
	int offsetSnd = 0;

	Ciphertext aux;							// ciphertext auxiliar folosite in adunare
	aux.setContext(fst.c.getContext());

	uint64_t defLen = fst.c.getContext().getDefaultN();	// dimensiunea unui chunk de ciphertext

	for (int digit = 0; digit < rez -> digitLen.size(); digit++) {

		rez -> digitLen[digit] = 0;

		if (digit < fstDlen) {

			aux.setValues(fstv + offsetFst * defLen, defLen * (fst.digitLen[digit]));
			aux.setBitlen(fstbl + offsetFst * defLen, defLen * (fst.digitLen[digit]));

			rez -> c += aux;

			rez -> digitLen[digit] += fst.digitLen[digit];
			offsetFst += fst.digitLen[digit];
		}

		if (digit < sndDlen) {

			aux.setValues(sndv + offsetSnd * defLen, defLen * (snd.digitLen[digit]));
			aux.setBitlen(sndbl + offsetSnd * defLen, defLen * (snd.digitLen[digit]));

			rez -> c += aux;

			rez -> digitLen[digit] += snd.digitLen[digit];
			offsetSnd += snd.digitLen[digit];
		}
	}

	return *rez;
}

void FHEuint::save(std::string fileName, const FHEuint & toSave, bool overwriteExistingFile) {

	// formatul fisierului:
	// bytii 0 - 3 : identificarea fisierului: tot timpul HEUI
	// bytii 4 - 7 = digitCnt: numarul de cifre in baza 2 ale numarului decriptat
	// urmatorii digitCnt * 4 byti: elementele corespunzatoare atributului digitLen ale numarului
	// urmatorii 8 byti = c.len = atributul len al ciphertet ului
	// urmatorii c.len * 8 byti: c.v = valorile din array ul v al ciphertext ului
	// urmatorii c.len * 8 byti: c.bitlen = valorile din array ul bitlen al ciphertext ului
	// urmatorii 8 byti: c.certFHEcontext.N
	// urmatorii 8 byti: c.certFHEcontext.D

	std::fstream saveFile;

	try {
		saveFile.open(fileName, std::ios::binary | std::ios::out | (overwriteExistingFile ? std::ios::trunc : 0));
	}
	catch (...) {
		throw;
	}

	saveFile.write("HEUI", 4);

	int digitCnt = toSave.digitLen.size();
	saveFile.write((char *)&digitCnt, 4);

	std::cout << digitCnt << '\n';

	const std::vector<int> & dlen = toSave.digitLen;

	for (int i = 0; i < digitCnt; i++) {
		std::cout << dlen[i] << " ";
		saveFile.write((char *)&dlen[i], 4);
	}
	std::cout << '\n';

	uint64_t cLen = toSave.c.getLen();
	saveFile.write((char *)&cLen, 8);

	std::cout << cLen << '\n';

	uint64_t * v = toSave.c.getValues();
	uint64_t * bl = toSave.c.getBitlen(); 

	for (uint64_t i = 0; i < cLen; i++) 
		saveFile.write((char *)&v[i], 8);

	for (uint64_t i = 0; i < cLen; i++)
		saveFile.write((char *)&bl[i], 8);

	uint64_t contextN = toSave.c.getContext().getN();
	uint64_t contextD = toSave.c.getContext().getD();

	saveFile.write((char *)&contextN, 8);
	saveFile.write((char *)&contextD, 8);

	std::cout << contextN << " " << contextD;

	saveFile.close();
}

FHEuint * FHEuint::load(std::string fileName) {

	std::fstream loadFile;
	
	try {
		loadFile.open(fileName, std::ios::in | std::ios::binary);
	}
	catch (...) {
		throw;
	}

	char id[4];
	loadFile.read(id, 4);

	if (id[0] != 0x48 || id[1] != 0x45 || id[2] != 0x55 || id[3] != 0x49)
		throw invalid_argument("fisierul primit nu contine un obiect de tip FHEint");

	FHEuint * loaded = new FHEuint;

	int digitCnt = 0;
	loadFile.read((char *)&digitCnt, 4);

	std::cout << '\n' << digitCnt << '\n';

	loaded -> digitLen.resize(digitCnt);

	int auxDigitLen = 0;
	for (int i = 0; i < digitCnt; i++) {

		loadFile.read((char *)&auxDigitLen, 4);
		loaded -> digitLen[i] = auxDigitLen;

		std::cout << auxDigitLen << " ";
	}
	std::cout << '\n';
	
	uint64_t cLen = 0;
	loadFile.read((char *)&cLen, 8);

	std::cout << cLen << '\n';

	uint64_t * v = new uint64_t[cLen];
	uint64_t * bl = new uint64_t[cLen];

	for (uint64_t i = 0; i < cLen; i++)
		loadFile.read((char *)(v + i), 8);

	for (uint64_t i = 0; i < cLen; i++)
		loadFile.read((char *)(bl + i), 8);

	uint64_t contextN = 0;
	loadFile.read((char *)&contextN, 8);

	uint64_t contextD = 0;
	loadFile.read((char *)&contextD, 8);

	std::cout << contextN << " " << contextD;

	Context loadedContex(contextN, contextD);
	loaded -> c.setContext(loadedContex);

	loaded -> c.setValues(v, cLen);
	loaded -> c.setBitlen(bl, cLen);

	return loaded;
}
