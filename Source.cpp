#include <iostream>
#include <vector>
#include "certFHE.h"
#include <random>

#define max(x, y) (x < y ? y : x)
#define min(x, y) (x < y ? x : y)

using namespace certFHE;

SecretKey * sek; // de test
Context * ctt; // de test

// am conceput un model pentru operatii cu numere naturale
//
// dorim ca serverul sa poate executa operatii cu acele numere
// care se afla in forma criptata
// iar la returnarea catre client sa poata fi decriptat direct rezultatul 
//
// am construit o clasa comuna si pentru client si pt server
// o parte din metode (constructori) au sens sa fie folosite
// (in cea mai mare parte) de client, iar 
// altele au sens sa fie folosite (in cea mai mare parte) de server
class FHEuint {

private:

	Ciphertext c;				// ciphertext ul numarului (care contine cifrele in baza 2 ale numarului)

	std::vector<int> digitLen;  // delimitarile intre cifrele in baza 2 ale numarului
								// fiecare cifra va fi compusa din (1+) chunks de lungime defLen
								// care vor fi adunate la decriptare
								//
								// digitLen[i] = k <=> cifra k (in stil Big Endian) a numarului
								//                     este compusa din k chunks de lungime defLen
								//
								// am ales sa folosesc vector in loc de array pentru 
								// ca in urma operatiilor e posibil sa apara operatii de resize des
								// care sunt mai eficient executate de clasa vector decat manual

	// metoda preluata din SecretKey.cpp cu 2 modificari:
	// 1. la inceput nu se mai verifica len == defLen deoarece realizez verificarea din functia apelanta
	// 2. retin in variabila carry overflow ul de la adunarea modulo 2
	uint64_t decrypt(uint64_t* v, uint64_t len, uint64_t defLen, uint64_t n, uint64_t d, uint64_t* s, uint64_t* bitlen, uint64_t * carry);

public:

	// constructor empty
	FHEuint(){
	}

	// constructor apelat (in mod normal) in client-side
	// nu ne dorim ca serverul sa aiba cheia in memorie
	// in niciun moment
	FHEuint(uint64_t toConvert, SecretKey * sk, Context * ct);

	// constructor de copiere
	FHEuint(const FHEuint & toCopy);

	FHEuint & operator = (const FHEuint & toCopy);

	// voi returna o referinta la rezultatul care sta in heap
	// pentru a evita copierea unui rezultat de dimensiune mare
	FHEuint & operator * (const FHEuint & snd) const;

	FHEuint & operator *= (const FHEuint & snd);

	// voi decripta pe rand fiecare dintre cifrele in baza 2, delimitate cu digitLen
	// pentru decriptare voi folosi o versiune modificata a functiei decrypt 
	// din fisierul sursa original SecretKey.cpp, linia 104
	// modificarea consta in returnarea intr un intreg dat ca parametru overflow ul de la adunare (carry ul)
	// (adunarea de pe linia 139)
	uint64_t decrypt(SecretKey * sk); 

	// pentru afisarea decriptata a cifrelor
	void showDigits(SecretKey * sk);

	// responsabilitatea caller ului sa se asigure ca fst si snd 
	// au fost criptate in acelasi context
	friend FHEuint * multiply(const FHEuint * fst, const FHEuint * snd);
};

uint64_t FHEuint::decrypt(uint64_t* v, uint64_t len, uint64_t defLen, uint64_t n, uint64_t d, uint64_t* s, uint64_t* bitlen, uint64_t * carry) {
	//if (len == defLen)
	//	return defaultN_decrypt(v, len, n, d, s, bitlen);


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
	this -> c.setContext(toCopy.c.getContext());  // la copierea Ciphertext, 
												  // nu se copiaza si contextul
												  // trebuie sa il copiez manual
	this -> digitLen = toCopy.digitLen;
}

FHEuint::FHEuint(uint64_t toConvert, SecretKey * sk, Context * ct) {

	Plaintext aux(toConvert & 1);
	this -> c = sk -> encrypt(aux); // la atribuire nu se copiaza si contextul, trb sa fac asta manual
	this -> c.setContext(*ct);

	toConvert >>= 1;
	this->digitLen.push_back(1);

	while (toConvert) {

		aux = Plaintext(toConvert & 1);
		this->c += sk -> encrypt(aux);

		toConvert >>= 1;
		this->digitLen.push_back(1);
	}
}

FHEuint & FHEuint::operator = (const FHEuint & toCopy) {

	// posibil bug in overload pe = si in setcontext in Ciphertext.cpp
	// concluzie: va trebui sa copiez continutul contextului fiecarui FHEuint pe rand
	// intrucat ar aparea probleme la folosirea directa a operatorului de atribuire
	//
	// stergerea valorilor vechi este realizata de setterii corespunzatori din clasa Ciphertext
	this -> c.setValues(toCopy.c.getValues(), toCopy.c.getLen());
	this -> c.setBitlen(toCopy.c.getBitlen(), toCopy.c.getLen());
	this -> c.setContext(toCopy.c.getContext());  

	this -> digitLen = toCopy.digitLen;

	return *this;
}

uint64_t FHEuint::decrypt(SecretKey * sk) {

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

			auxPlain = sk -> decrypt(aux);
			//std::cout << "toret " << toReturn << " ";
			//std::cout << "digit " << digit << " value " << (int)auxPlain.getValue() << '\n';

			if ((int)auxPlain.getValue() == 1)
				toReturn += (1 << digit);
		}
		else {

			uint64_t carry = 0;

			decryptedDigit = this -> decrypt(v + offset, currentDigitLen, defLen, this -> c.getContext().getN(), this -> c.getContext().getD(), sk -> getKey(), bl + offset, &carry);

			toReturn += (carry << (digit + 1));
			toReturn += (decryptedDigit << digit);
			//std::cout << "toret " << toReturn << " ";
			//std::cout << "digit " << digit << " value " << decryptedDigit << " carry " << carry << '\n';
		}

		offset += currentDigitLen;
	}

	return toReturn;
}

void FHEuint::showDigits(SecretKey * sk) {

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

			std::cout << sk -> decrypt(ca) << " ";
		}
		std::cout << '\n';

		offset += digitLen[digit];
	}
}

FHEuint * multiply(const FHEuint * fst, const FHEuint * snd) {

	// initializari de vaariabile auxiliare

	FHEuint * rez = new FHEuint;				// rezultatul inmultirii
	rez -> c.setContext(fst -> c.getContext());

	uint64_t * fstv = fst -> c.getValues();		// ciphertext ul primului nr
	uint64_t * sndv = snd -> c.getValues();		// ciphertext ul celui de al doilea nr

	uint64_t * fstbl = fst -> c.getBitlen();	// bitlen corespunzator primului nr
	uint64_t * sndbl = snd -> c.getBitlen();	// bitlen corespunzator celui de al doiela nr

	std::vector<int> fstDigitLenPartialSum(fst -> digitLen.size());
	std::vector<int> sndDigitLenPartialSum(snd -> digitLen.size());

	Ciphertext fstaux, sndaux;	// ciphertext uri auxiliare folosite in inmultire
	fstaux.setContext(fst -> c.getContext());
	sndaux.setContext(snd -> c.getContext());

	uint64_t defLen = fst -> c.getContext().getDefaultN();	// dimensiunea unui chunk de ciphertext

	// preprocesari

	// am nevoie de pozitia in ciphertext a fiecarei cifre in baza 2
	// DigitLen furnizeaza numai lungimea fiecarei cifre 
	// DigitLenPartialSum furnizeaza pozitia de inceput a fiecarei cifre
	// (pozitie exprimata in nr de chunks de lungime defLen de la inceputul chiphertextului)
	
	fstDigitLenPartialSum[0] = 0;
	for (int i = 1; i < fstDigitLenPartialSum.size(); i++)
		fstDigitLenPartialSum[i] = fstDigitLenPartialSum[i - 1] + (fst -> digitLen[i - 1]);

	sndDigitLenPartialSum[0] = 0;
	for (int i = 1; i < sndDigitLenPartialSum.size(); i++)
		sndDigitLenPartialSum[i] = sndDigitLenPartialSum[i - 1] + (snd -> digitLen[i - 1]);
	
	// realizarea inmultirii
	// for urile sunt plasate a.i. adunarea produselor intermediare sa necesite 
	//                             cat mai putine structuri auxiliare

	int n = fstDigitLenPartialSum.size();
	int m = sndDigitLenPartialSum.size();

	//std::cout << " n si m " << n << " " << m << "\n\n";

	for (int rezDigit = 0; rezDigit < m + n; rezDigit++) {

		for (int fstDigit = max(0, rezDigit - m - 1); fstDigit <= min(n - 1, rezDigit); fstDigit++)
			for (int sndDigit = min(m - 1, rezDigit); sndDigit >= max(0, rezDigit - n - 1); sndDigit--)
				
				if (fstDigit + sndDigit == rezDigit) {

					//std::cout << " fstd sndd " << fstDigit << " " << sndDigit << '\n';

					for (int i = 0; i < fst -> digitLen[fstDigit]; i++) {
						for (int j = 0; j < snd -> digitLen[sndDigit]; j++) {

							int offsetFst = fstDigitLenPartialSum[fstDigit] + i;
							int offsetSnd = sndDigitLenPartialSum[sndDigit] + j;

							fstaux.setValues(fstv + offsetFst * defLen, defLen);
							fstaux.setBitlen(fstbl + offsetFst * defLen, defLen);

							//std::cout << "offsetFst offsetSnd " << offsetFst << " " << offsetSnd << '\n';
							//----
							/*Ciphertext ac;
							ac.setContext(fst -> c.getContext());
							ac.setValues(fstaux.getValues(), defLen);
							ac.setBitlen(fstaux.getBitlen(), defLen);

							std::cout << " fst val: " << sek -> decrypt(ac);*/
							//----

							sndaux.setValues(sndv + offsetSnd * defLen, defLen);
							sndaux.setBitlen(sndbl + offsetSnd * defLen, defLen);

							//----
							/*ac.setValues(sndaux.getValues(), defLen);
							ac.setBitlen(sndaux.getBitlen(), defLen);

							std::cout << " snd val: " << sek -> decrypt(ac);*/
							//----

							fstaux *= sndaux;

							//----
							/*ac.setValues(fstaux.getValues(), defLen);
							ac.setBitlen(fstaux.getBitlen(), defLen);

							std::cout << " decriptat: " << sek -> decrypt(ac) << '\n';*/
							//----

							rez -> c += fstaux;

							if (rezDigit >= rez -> digitLen.size())
								rez -> digitLen.push_back(1);
							else
								rez -> digitLen[rezDigit] += 1;
						}
					}
				}

	}

	return rez;
}

FHEuint & FHEuint::operator * (const FHEuint & snd) const {

	FHEuint * rez = multiply(this, &snd);
	return *rez;
}

/* consumul de memorie s-ar putea optimiza */
FHEuint & FHEuint::operator *= (const FHEuint & snd) {

	FHEuint * rez = multiply(this, &snd);

	this -> c.setValues(rez -> c.getValues(), rez -> c.getLen());
	this -> c.setBitlen(rez -> c.getBitlen(), rez -> c.getLen());
	this -> c.setContext(rez -> c.getContext());

	this -> digitLen = rez -> digitLen;

	delete rez;
	
	/* probleme de rezolvat cu atribuirea */
	return *this;
}

void multiplyTest() {

	for (int t = 0; t < 10; t++) {

		uint64_t * nr = new uint64_t[20];
		for (int i = 0; i < 8; i++)
			nr[i] = rand() % 10;

		FHEuint * u = new FHEuint[20];
		for (int i = 0; i < 8; i++)
			u[i] = FHEuint(nr[i], sek, ctt);

		FHEuint * u2 = multiply(u, u + 1);
		FHEuint * u3 = multiply(u + 2, u + 3);
		FHEuint * u4 = multiply(u + 4, u + 5);
		FHEuint * u5 = multiply(u + 6, u + 7);

		FHEuint * u8 = multiply(u2, u3);
		FHEuint * u9 = multiply(u4, u5);

		FHEuint * u10 = multiply(u8, u9);

		if (u10 -> decrypt(sek) != nr[0] * nr[1] * nr[2] * nr[3] * nr[4] * nr[5] * nr[6] * nr[7])
			std::cout << "not ok\n";
		else
			std::cout << "ok\n";

		//std::cout << u2 -> decrypt(sek) << " " << nr[0] * nr[1] << '\n';
	}
	std::cout << "done\n";
}

int main() {

	Library::initializeLibrary();
	Context context(1247, 16);
	SecretKey sk(context);

	sek = &sk;
	ctt = &context;

	// testMultiply();
	FHEuint * x = new FHEuint(18, sek, ctt);
	FHEuint k(100, &sk, &context);
	*x *= k;
	
	std::cout << x -> decrypt(sek);
	
	

	//std::cout << x.c.getContext().getDefaultN() << '\n';

	//FHEuint * z = multiply(x, &y);
	
	/*int m = 10;
	int n = 7;
	
	for (int k = 0; k <= m + n; k++) {
		for (int a = max(0, k - m); a <= min(n, k); a++) 
			for (int b = min(m, k); b >= max(0, k - n); b--)
				if(a + b == k)
					std::cout << a << " " << b << " | ";
			
		std::cout << '\n';
	}*/

	return 0;
}
