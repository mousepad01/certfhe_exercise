#ifndef FHEUINT
#define FHEUINT

#include <iostream>
#include <vector>
#include "certFHE.h"
#include <string>
#include <random> // pentru teste

#define max(x, y) (x < y ? y : x)
#define min(x, y) (x < y ? x : y)

using namespace certFHE;

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

public:

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

	//---------- CONSTRUCTORI & DESTRUCTORI ---------------

	// constructor empty
	FHEuint() {}

	// constructor apelat (in mod normal) in client-side
	// nu ne dorim ca serverul sa aiba cheia in memorie
	// in niciun moment
	FHEuint(uint64_t toConvert, SecretKey & sk, Context & ct);

	// constructor de copiere
	FHEuint(const FHEuint & toCopy);

	// destructor: va pune 0 in zona de memorie a vectorului digitLen dupa stergere
	~FHEuint();

	//---------- OVERLOAD OPERATORI ---------------

	FHEuint & operator = (const FHEuint & toCopy);

	// voi returna o referinta la rezultatul care sta in heap
	// pentru a evita copierea unui rezultat de dimensiune mare
	FHEuint & operator * (const FHEuint & snd) const;

	FHEuint & operator *= (const FHEuint & snd);

	// voi returna o referinta la rezultatul care sta in heap
	// pentru a evita copierea unui rezultat de dimensiune mare
	FHEuint & operator + (const FHEuint & snd) const;

	FHEuint & operator += (const FHEuint & snd);

	//---------- METODE PUBLICE ---------------

	// returneaza numarul de cifre in baza 2 ale numarului corespunzator decriptat
	int getDigitsCnt();

	void permuteKey(const Permutation & p);

	// voi returna o referinta la rezultatul care sta in heap
	// pentru a evita copierea unui rezultat de dimensiune mare
	FHEuint & getPermutedCopy(const Permutation & p); // const

	// voi decripta pe rand fiecare dintre cifrele in baza 2, delimitate cu digitLen
	// pentru decriptare voi folosi o versiune modificata a functiei decrypt 
	// din fisierul sursa original SecretKey.cpp, linia 104
	// modificarea consta in returnarea intr un intreg dat ca parametru overflow ul de la adunare (carry ul)
	// (adunarea de pe linia 139)
	uint64_t decrypt(SecretKey & sk);

	// pentru afisarea decriptata a cifrelor
	void showDigits(SecretKey & sk) const;

	//---------- FUNCTII FRIEND ---------------

	// responsabilitatea caller ului sa se asigure ca fst si snd 
	// au fost criptate in acelasi context
	friend FHEuint & multiply(const FHEuint & fst, const FHEuint & snd);

	// responsabilitatea caller ului sa se asigure ca fst si snd 
	// au fost criptate in acelasi context
	friend FHEuint & add(const FHEuint & fst, const FHEuint & snd);

	//---------- METODE STATICE ---------------

	// pentru a salva intr-un fisier binar numarul
	static void save(std::string fileName, const FHEuint & toSave, bool overwriteExistingFile = false);

	// pentru a incarca dintr-un fisier binar numarul
	static FHEuint * load(std::string fileName);
};

#endif