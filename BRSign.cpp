/*
	A simple implementation of my paper's so-called blind ring signature
	Reference code:
		------
		sk_1.cpp - Sakai-Kasahara IBE (using a type-1 pairing)
		------
	Usage:
		Compile with modules as specified below

		For MR_PAIRING_SS2 curves
		g++ -O2 BRSign.cpp ss2_pair.cpp ec2.cpp gf2m4x.cpp gf2m.cpp big.cpp miracl.a

		For MR_PAIRING_SSP curves
		cl /O2 /GX sk_1.cpp ssp_pair.cpp ecn.cpp zzn2.cpp zzn.cpp big.cpp miracl.lib
*/
#include <iostream>
#include <ctime>

//********* CHOOSE JUST ONE OF THESE **********
#define MR_PAIRING_SS2			// AES-80 or AES-128 security GF(2^m) curve
//#define AES_SECURITY 80			// OR
#define AES_SECURITY 128

//#define MR_PAIRING_SSP		// AES-80 or AES-128 security GF(p) curve
//#define AES_SECURITY 80		// OR
//#define AES_SECURITY 128
//*********************************************

#include "pairing_1.h"

#define RING_SIZE 50
#define ROUND 50
char *m = (char *)"the bitcoin address of payee";
clock_t t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14;
double tKeyGen,tHash_m,tBlind_m,tBRing_sign,tBRing_verify,tUnblind_sig,tFinal_verify;

int main()
{
	for (int i = 0; i < ROUND; ++i)
	{
		PFC pfc(AES_SECURITY);		// initialise pairing-friendly curve

		Big z[RING_SIZE],b,alpha,x,y;
		G1 P,Z[RING_SIZE],hm,_hm;
		GT g;

	// Setup
		time_t seed;
		time(&seed);
		irand((long)seed);

		Big q = pfc.order();
		cout << endl << "------ the order of G1 is q ------" << endl << endl;
		cout << q;
		cout << endl;
		pfc.random(P);
		cout << endl << "------ the point P of G1 ------" << endl << endl;
		P.g.getxy(x,y);
		cout << "x: ";
		cout << x;
		cout << endl;
		cout << "y: ";
		cout << y;
		cout << endl;
		g = pfc.pairing(P,P);
		pfc.precomp_for_power(g);
		pfc.precomp_for_mult(P);

	// KeyGen
		t1 = clock();
		for (int i = 0; i < RING_SIZE; ++i)	// generate public-private keys of signers in ring
		{
			z[i] = rand(q);
			Z[i] = pfc.mult(P,z[i]);
		}
		t2 = clock();
		cout << endl << "------ private-public keys of signers in ring with size: " << RING_SIZE << " ------" << endl << endl;
		for (int i = 0; i < RING_SIZE; ++i)
		{
			cout << "|----- private_key and public__key ------" << endl;
			cout << z[i];
			cout << endl;
			Z[i].g.getxy(x,y);
			cout << "x: ";
			cout << x;
			cout << endl;
			cout << "y: ";
			cout << y;
			cout << endl;
		}

	// BRSign (which contains four sub-algorithms)
		// blind message
		t3 = clock();
		b = pfc.hash_to_group(m);
		hm = pfc.mult(P,b);	// map the message to G1
		t4 = clock();
		cout << endl << "------ original message ------" << endl << endl;
		hm.g.getxy(x,y);
		cout << x;
		cout << endl;
		cout << y;
		cout << endl;
		pfc.random(alpha);
		cout << endl << "------ blind factor ------" << endl << endl;
		cout << alpha;
		cout << endl;
		t5 = clock();
		_hm = pfc.mult(hm,alpha);	// using blind factor blind message
		t6 = clock();
		cout << endl << "------ blind message ------" << endl << endl;
		_hm.g.getxy(x,y);
		cout << x;
		cout << endl;
		cout << y;
		cout << endl;

		// blind sign (suppose the real signer of ring is index of 0, i.e., z[0] with Z[0])
		t7 = clock();
		Big u;
		LOOP:
		u = rand(q);
		G1 temp_bs = pfc.mult(P,u);
		pfc.start_hash();
		pfc.add_to_hash(pfc.pairing(_hm,temp_bs));
		Big c1 = pfc.finish_hash_to_group();
		Big s[RING_SIZE],c[RING_SIZE];	// the random values of Ring Signature
		c[1] = c1;

		for (int i = 1; i < RING_SIZE; ++i)
		{
			s[i] = rand(q);
			pfc.start_hash();
			pfc.add_to_hash(pfc.pairing(_hm,pfc.mult(Z[i],s[i]+c[i])));
			c[(i+1)%RING_SIZE]=pfc.finish_hash_to_group();
		}

		s[0] = modmult(z[0],c[0],q);
		Big var;
		subtract(u.getbig(),s[0].getbig(),var.getbig());
		s[0] = modmult(var,inverse(z[0],q),q);
		t8 = clock();
		cout << endl << "------ blind signature _Sigma=(c1,s1,s2,...,sN) ------" << endl << endl;
		for (int i = 0; i < RING_SIZE; ++i)	// print c[i]
		{
			printf("c%2d:", i);
			cout << c[i];
			cout << endl;
		}
		for (int i = 0; i < RING_SIZE; ++i)	// print s[i]
		{
			printf("s%2d:", i);
			cout << s[i];
			cout << endl;
		}

		// blind verify
		t9 = clock();
		for (int i = 1; i < RING_SIZE; ++i)
		{
			pfc.start_hash();
			pfc.add_to_hash(pfc.pairing(_hm,pfc.mult(Z[i],s[i]+c[i])));
			c[(i+1)%RING_SIZE]=pfc.finish_hash_to_group();
		}
		t10 = clock();

		cout << endl << "------ using blind signature to verify ------" << endl << endl;
		for (int i = 0; i < RING_SIZE; ++i)	// print c[i]
		{
			printf("c%2d:", i);
			cout << c[i];
			cout << endl;
		}
		for (int i = 0; i < RING_SIZE; ++i)	// print s[i]
		{
			printf("s%2d:", i);
			cout << s[i];
			cout << endl;
		}

		G1 temp_bv = pfc.mult(Z[0],s[0]+c[0]);
		pfc.start_hash();
		pfc.add_to_hash(pfc.pairing(_hm,temp_bv));
		Big BVerify = pfc.finish_hash_to_group();
		cout << "BVerify: ";
		cout << BVerify;
		cout << endl;
		if (temp_bs != temp_bv)	// don't satisfy the closure condition of ring signature
		{
			goto LOOP;
		}

		// unblind (i.e. convert _Sigma to Sigma )
		t11 = clock();
		Big s_final[RING_SIZE],c_final[RING_SIZE];	// converted s[RING_SIZE] and c[RING_SIZE]
		for (int i = 0; i < RING_SIZE; ++i)
		{
			add(modmult(alpha,s[i],q).getbig(),modmult((alpha-1),c[i],q).getbig(),s_final[i].getbig());
			Big var(1);
			s_final[i] = modmult(s_final[i], var, q);
			c_final[i] = c[i];
		}
		t12 = clock();

		cout << endl << "------ unblind signature Sigma=(c1,s1,s2,...,sN) ------" << endl << endl;
		for (int i = 0; i < RING_SIZE; ++i)	// print c_final[i]
		{
			printf("c%2d:", i);
			cout << c_final[i];
			cout << endl;
		}
		for (int i = 0; i < RING_SIZE; ++i)	// print s_final[i]
		{
			printf("s%2d:", i);
			cout << s_final[i];
			cout << endl;
		}

	// Verify
		t13 = clock();
		for (int i = 1; i < RING_SIZE; ++i)
		{
			pfc.start_hash();
			pfc.add_to_hash(pfc.pairing(hm,pfc.mult(Z[i],s_final[i]+c_final[i])));
			c_final [(i+1)%RING_SIZE]=pfc.finish_hash_to_group();
		}
		t14 = clock();

		cout << endl << "------ using unblind signature to verify ------" << endl << endl;
		for (int i = 0; i < RING_SIZE; ++i)	// print c[i]
		{
			printf("c%2d:", i);
			cout << c_final[i];
			cout << endl;
		}
		for (int i = 0; i < RING_SIZE; ++i)	// print s[i]
		{
			printf("s%2d:", i);
			cout << s_final[i];
			cout << endl;
		}

		G1 temp_v = pfc.mult(Z[0],s_final[0]+c_final[0]);
		pfc.start_hash();
		pfc.add_to_hash(pfc.pairing(hm,temp_v));
		Big Verify = pfc.finish_hash_to_group();
		cout << "Verify: ";
		cout << Verify;
		cout << endl;



		tKeyGen += double(t2-t1);
		tHash_m += double(t4-t3);
		tBlind_m += double(t6-t5);
		tBRing_sign += double(t8-t7);
		tBRing_verify += double(t10-t9);
		tUnblind_sig += double(t12-t11);
		tFinal_verify += double(t14-t13);

		cout << endl << "==========================================" << endl;
		cout         << "                the cost                  " << endl;
		cout         << "==========================================" << endl;
		cout         << "KeyGen:      " << (double)((t2-t1))/CLOCKS_PER_SEC    << endl;
		cout         << "Hash m:      " << (double)((t4-t3))/CLOCKS_PER_SEC    << endl;
		cout         << "Blind m:     " << (double)((t6-t5))/CLOCKS_PER_SEC    << endl;
		cout         << "BRing sign:  " << (double)((t8-t7))/CLOCKS_PER_SEC    << endl;
		cout         << "BRing verify:" << (double)((t10-t9))/CLOCKS_PER_SEC   << endl;
		cout         << "Unblind sig: " << (double)((t12-t11))/CLOCKS_PER_SEC  << endl;
		cout         << "Final verify:" << (double)((t14-t13))/CLOCKS_PER_SEC  << endl;
	}

	cout << endl << "==========================================" << endl;
	cout         << "            the average cost              " << endl;
	cout         << "==========================================" << endl;
	cout         << "KeyGen:      " << tKeyGen/ROUND             << endl;
	cout         << "Hash m:      " << tHash_m/ROUND             << endl;
	cout         << "Blind m:     " << tBlind_m/ROUND            << endl;
	cout         << "BRing sign:  " << tBRing_sign/ROUND         << endl;
	cout         << "BRing verify:" << tBRing_verify/ROUND       << endl;
	cout         << "Unblind sig: " << tUnblind_sig/ROUND        << endl;
	cout         << "Final verify:" << tFinal_verify/ROUND       << endl;

	return 0;
}
