/*
	A simple implementation of IBS
	Reference code:
		------
		sk_1.cpp - Sakai-Kasahara IBE (using a type-1 pairing)
		------
	Usage:
		Compile with modules as specified below

		For MR_PAIRING_SS2 curves
		g++ -O2 ibs.cpp ss2_pair.cpp ec2.cpp gf2m4x.cpp gf2m.cpp big.cpp miracl.a

		For MR_PAIRING_SSP curves
		cl /O2 /GX sk_1.cpp ssp_pair.cpp ecn.cpp zzn2.cpp zzn.cpp big.cpp miracl.lib
*/
#include <iostream>
#include <ctime>

//********* CHOOSE JUST ONE OF THESE **********
#define MR_PAIRING_SS2			// AES-80 or AES-128 security GF(2^m) curve
#define AES_SECURITY 80			// OR
//#define AES_SECURITY 128

//#define MR_PAIRING_SSP		// AES-80 or AES-128 security GF(p) curve
//#define AES_SECURITY 80		// OR
//#define AES_SECURITY 128
//*********************************************

#include "pairing_1.h"

#define ROUND 50
char *ID = (char *)"#123456789";
char *m = (char *)"message";
clock_t t1,t2,t3,t4;
double Sign,Verify;

int main()
{
	for (int i = 0; i < ROUND; ++i)
	{
		PFC pfc(AES_SECURITY);		// initialise pairing-friendly curve

		Big q,alpha,beta,x,y;
		G1 g,ga,gb;
		GT gt,gta;

	// Setup
		time_t seed;
		time(&seed);
		irand((long)seed);

		q = pfc.order();
		cout << endl << "------ the order of G1 is q ------" << endl << endl;
		cout << q;
		cout << endl;
		pfc.random(g);
		cout << endl << "------ the generator of G1 ------" << endl << endl;
		g.g.getxy(x,y);
		cout << "x: ";
		cout << x;
		cout << endl;
		cout << "y: ";
		cout << y;
		cout << endl;
		gt = pfc.pairing(g,g);
		pfc.precomp_for_power(gt);
		pfc.precomp_for_mult(g);
		alpha = rand(q);
		beta = rand(q);
		gta = pfc.power(gt,alpha);
		gb = pfc.mult(g,beta);
		ga = pfc.mult(g,alpha);
		cout << endl << "------ the pp of system ------" << endl << endl;
		cout << "g:";
		cout << x;
		cout << ",";
		cout << y;
		cout << endl;
		cout << "e(g,g)^alpha:";
		cout << gta.g;
		cout << endl;
		cout << "g^beta:";
		gb.g.getxy(x,y);
		cout << x;
		cout << ",";
		cout << y;
		cout << endl;
		cout << "h:{0,1}*--->G1" << endl;
		cout << endl << "------ the MSK of system ------" << endl << endl;
		cout << "g^alpha:";
		ga.g.getxy(x,y);
		cout << x;
		cout << ",";
		cout << y;
		cout << endl;

	// PrivateKeyGen
		Big t;
		G1 K0,K1,K2;
		t = rand(q);
		K0 = ga + pfc.mult(g,modmult(beta,t,q));
		K1 = pfc.mult(g,t);
		K2 = pfc.mult(pfc.mult(g,pfc.hash_to_group(ID)),t);
		cout << endl << "------ the private of ID ------" << endl << endl;
		cout << "K0:";
		K0.g.getxy(x,y);
		cout << x;
		cout << ",";
		cout << y;
		cout << endl;
		cout << "K1:";
		K1.g.getxy(x,y);
		cout << x;
		cout << ",";
		cout << y;
		cout << endl;
		cout << "K2:";
		K2.g.getxy(x,y);
		cout << x;
		cout << ",";
		cout << y;
		cout << endl;

	// Sign
		t1 = clock();
		Big tau;
		G1 S0,S1,S2,S3;
		tau = rand(q);
		S0 = K0 + pfc.mult(gb,tau);
		S1 = K1;
		S2 = pfc.mult(g,tau);
		S3 = K2 + pfc.mult(pfc.mult(g,pfc.hash_to_group(m)),tau);
		t2 = clock();

		cout << endl << "------ the signature ------" << endl << endl;
		cout << "ID:" << ID << endl;
		cout << "S0:";
		S0.g.getxy(x,y);
		cout << x;
		cout << ",";
		cout << y;
		cout << endl;
		cout << "S1:";
		S1.g.getxy(x,y);
		cout << x;
		cout << ",";
		cout << y;
		cout << endl;
		cout << "S2:";
		S2.g.getxy(x,y);
		cout << x;
		cout << ",";
		cout << y;
		cout << endl;
		cout << "S3:";
		S3.g.getxy(x,y);
		cout << x;
		cout << ",";
		cout << y;
		cout << endl;

	// Verify
		t3 = clock();
		GT v = (pfc.pairing(S0,g)*pfc.pairing(S3,g))/(pfc.pairing(S1,gb+pfc.mult(g,pfc.hash_to_group(ID)))*pfc.pairing(S2,gb+pfc.mult(g,pfc.hash_to_group(m))));
		t4 = clock();
		if (v==gta)
		{
			cout << endl << "signature ture" << endl;
		}
		else
		{
			cout << endl << "signature false" << endl;
		}
		
		Sign += double(t2-t1);
		Verify += double(t4-t3);
	}

	cout << endl << "==========================================" << endl;
	cout         << "          the average cost (ms)           " << endl;
	cout         << "==========================================" << endl;
	cout         << "Sign:   " << Sign/ROUND                     << endl;
	cout         << "Verify: " << Verify/ROUND                   << endl;

	return 0;
}
