#include <iostream>
#include "FHEuint.h"

void mulTest(SecretKey & sek, SecretKey & sekp, Context & ctt, Permutation & perm) {

	for (int t = 0; t < 10; t++) {

		uint64_t * nr = new uint64_t[20];
		for (int i = 0; i < 8; i++) 
			nr[i] = rand() % 10;

		FHEuint * u = new FHEuint[20];
		for (int i = 0; i < 8; i++)
			u[i] = FHEuint(nr[i], sek, ctt);

		FHEuint & u2 = multiply(u[0], u[1]);
		FHEuint & u3 = multiply(u[2], u[3]);
		FHEuint & u4 = multiply(u[4], u[5]);
		FHEuint & u5 = multiply(u[6], u[7]);

		FHEuint & u8 = multiply(u2, u3);
		FHEuint & u9 = multiply(u4, u5);

		FHEuint & u10 = multiply(u8, u9);

		if (u10.decrypt(sek) != nr[0] * nr[1] * nr[2] * nr[3] * nr[4] * nr[5] * nr[6] * nr[7])
			std::cout << "not ok\n";
		else
			std::cout << "ok\n";

		//std::cout << u2 -> decrypt(sek) << " " << nr[0] * nr[1] << '\n';
	}
	std::cout << "done\n";
}

void addTest(SecretKey & sek, SecretKey & sekp, Context & ctt, Permutation & perm) {

	for (int t = 0; t < 100; t++) {

		uint64_t * nr = new uint64_t[16];

		FHEuint * u = new FHEuint[16];

		for (int i = 0; i < 16; i++) {

			nr[i] = rand();
			u[i] = FHEuint(nr[i], sek, ctt);
		}

		FHEuint & u1 = add(u[0], u[1]);
		FHEuint & u2 = add(u[2], u[3]);
		FHEuint & u3 = add(u[4], u[5]);
		FHEuint & u4 = add(u[6], u[7]);
		FHEuint & u5 = add(u[8], u[9]);
		FHEuint & u6 = add(u[10], u[11]);

		FHEuint & u7 = add(u1, u2);
		FHEuint & u8 = add(u3, u4);
		FHEuint & u9 = add(u5, u6);

		FHEuint & u10 = add(u7, u8);
		FHEuint & u11 = add(u10, u9);

		uint64_t realSum = 0;
		for (int i = 0; i < 12; i++)
			realSum += nr[i];

		if (u11.decrypt(sek) != realSum)
			std::cout << "problem\n";
		else
			std::cout << "ok\n";

		//std::cout << u11 -> decrypt(sek) << " " << realSum;
	}

	std::cout << "done\n";
}

void addMulTest(SecretKey & sek, SecretKey & sekp, Context & ctt, Permutation & perm) {

	for (int t = 0; t < 3; t++) {

		uint64_t * nr = new uint64_t[16];

		FHEuint * u = new FHEuint[16];

		for (int i = 0; i < 16; i++) {

			nr[i] = rand() % 100;
			u[i] = FHEuint(nr[i], sek, ctt);
		}

		FHEuint & u1 = add(u[0], u[1]);
		FHEuint & u2 = add(u[2], u[3]);
		FHEuint & u3 = add(u[4], u[5]);
		FHEuint & u4 = add(u[6], u[7]);
		FHEuint & u5 = add(u[8], u[9]);
		FHEuint & u6 = add(u[10], u[11]);

		FHEuint & u7 = add(u1, u2);
		FHEuint & u8 = add(u3, u4);
		FHEuint & u9 = add(u5, u6);

		FHEuint & u10 = add(u7, u8);
		FHEuint & u11 = add(u10, u9);

		u11 *= u5;

		FHEuint & u12 = add(u11, u11);

		uint64_t realSum = 0;
		for (int i = 0; i < 12; i++)
			realSum += nr[i];

		realSum *= 2 * (nr[8] + nr[9]);

		if (u12.decrypt(sek) != realSum)
			std::cout << "problem\n";
		else
			std::cout << "ok\n";

		//std::cout << u11 -> decrypt(sek) << " " << realSum;
	}

	std::cout << "done\n";
}

void addMulPermTest(SecretKey & sek, SecretKey & sekp, Context & ctt, Permutation & perm) {

	for (int t = 0; t < 3; t++) {

		uint64_t * nr = new uint64_t[16];

		FHEuint * u = new FHEuint[16];

		for (int i = 0; i < 16; i++) {

			nr[i] = rand() % 100;
			u[i] = FHEuint(nr[i], sek, ctt);
		}

		FHEuint & u1 = add(u[0], u[1]);
		FHEuint & u2 = add(u[2], u[3]);
		FHEuint & u3 = add(u[4], u[5]);
		FHEuint & u4 = add(u[6], u[7]);
		FHEuint & u5 = add(u[8], u[9]);
		FHEuint & u6 = add(u[10], u[11]);

		FHEuint & u7 = add(u1, u2);
		FHEuint & u8 = add(u3, u4);
		FHEuint & u9 = add(u5, u6);

		FHEuint & u10 = add(u7, u8);
		FHEuint & u11 = add(u10, u9);

		u11 *= u5;

		FHEuint & u12 = add(u11, u11);

		uint64_t realSum = 0;
		for (int i = 0; i < 12; i++)
			realSum += nr[i];

		realSum *= 2 * (nr[8] + nr[9]);

		FHEuint & cp = u12.getPermutedCopy(perm);

		if (u12.decrypt(sek) != realSum || u12.decrypt(sek) != cp.decrypt(sekp))
			std::cout << "problem\n";
		else
			std::cout << "ok\n";

		//std::cout << u11 -> decrypt(sek) << " " << realSum;
	}

	std::cout << "done\n";
}

int main3() {

	Library::initializeLibrary();
	Context context(1247, 16);
	SecretKey sk(context);

	Permutation p(context);
	SecretKey skp = sk.applyPermutation(p);

	mulTest(sk, skp, context, p);
	addTest(sk, skp, context, p);
	addMulTest(sk, skp, context, p);
	addMulPermTest(sk, skp, context, p);

	// testarea unui caz de exceptie

	std::cout << "se vor afisa mesaje de exceptie:\n";

	FHEuint x;
	try {
		x.decrypt(sk);
	}
	catch (invalid_argument & err) {
		std::cout << err.what() << '\n';
	}

	FHEuint y(17492, sk, context);
	try {
		x += y;
	}
	catch (invalid_argument & err) {
		std::cout << err.what() << '\n';
	}

	return 0;
}

