#include <iostream>
#include "certFHE.h"
#include "FHEstring.h"

int main2() {

	Library::initializeLibrary();
	Context context(1247, 16);
	SecretKey sk(context);
	Permutation p(context);
	SecretKey skp = sk.applyPermutation(p);

	std::string str = "abcdef";
	std::string str2 = ", si apoi am plecat";
	std::string str3 = "\nla mare!";

	FHEstring s(str, sk, context);
	FHEstring s2(str2, sk, context);
	FHEstring s3(str3, sk, context);

	s += s2 + s3;

	try {

		std::cout << s.decrypt(sk) << '\n';

		FHEstring & sp = s.getPermutedCopy(p);
		std::cout << sp.decrypt(skp) << '\n';

		FHEstring & s4 = s[{1, 3}];
		std::cout << s4.decrypt(sk) << '\n';

		s = s[{-5, -1}];
		std::cout << s.decrypt(sk) << '\n';

	}
	catch (out_of_range & err) {
		std::cout << err.what();
	}
	catch (...) {
		std::cout << "eroare neanticipata\n";
	}

	return 0;
}