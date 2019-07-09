/*
	A simple implementation of ECC (secp256k1 of bicoin) encryption and decryption of Elgamal Public Key Encryption Algorithm
	Reference code:
		------
		ecsgen.c
		ecsign.c
		ecsver.c
		------
	Usage:
		gcc -O2 ECCencryption.c miracl.a
*/

#include <stdio.h>
#include "miracl.h"
#include <time.h>

// bitcoin secp256k1 parameters
char A[] = "0";
char B[] = "7";
char P[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
char Q[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
char X[] = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
char Y[] = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

clock_t t1,t2,t3,t4;
double Enc,Dec;
#define ROUND 1000
#define MESSAGE_SIZE 50

int main(int argc, char const *argv[])
{
	big a,b,p,q,x,y,sk;
	epoint *g,*w,*pk;
	long seed;

	miracl *mip = mirsys(64,16);

	a = mirvar(0);
	b = mirvar(0);
	p = mirvar(0);
	q = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);
	sk = mirvar(0);

	instr(a,A);
	instr(b,B);
	instr(p,P);
	instr(q,Q);
	instr(x,X);
	instr(y,Y);

	// randomise
	printf("Enter 9 digit random number seed  = ");
	scanf("%ld",&seed);
	getchar();
	irand(seed);

	ecurve_init(a,b,p,MR_PROJECTIVE);	// initialise curve

	g = epoint_init();	// base point
	w = epoint_init();	// infinity point
	pk = epoint_init();	// public key point

	if (!epoint_set(x,y,0,g))	//initialise point of order q
	{
		printf("1. Problem - point (x,y) is not on the curve\n");
		exit(0);
	}
	ecurve_mult(q,g,w);
	if (!point_at_infinity(w))
	{
		printf("2. Problem - point (x,y) is not of order q\n");
		exit(0);
	}

// KeyGen
	bigrand(q,sk);
	ecurve_mult(sk,g,pk);

	printf("\n------ the private key ------\n\n");
	otnum(sk,stdout);
	printf("\n------ the public key ------\n\n");
	epoint_get(pk,x,y);	// uncompress point
	otnum(x,stdout);
	otnum(y,stdout);

// Encryption
	big m,r;
	epoint *m_point[MESSAGE_SIZE],*r_point,*cipher_point[MESSAGE_SIZE];
	m = mirvar(0);
	r = mirvar(0);
	for (int i = 0; i < MESSAGE_SIZE; ++i)
	{
		m_point[i] = epoint_init();
		cipher_point[i] = epoint_init();
	}
	r_point = epoint_init();

	for (int i = 0; i < ROUND; ++i)
	{
		t1 = clock();
		// generate message
		for (int i = 0; i < MESSAGE_SIZE; ++i)
		{
			bigrand(q,m);
			ecurve_mult(m,g,m_point[i]);
		}
		// generate random r
		bigrand(q,r);
		ecurve_mult(r,g,r_point);

		// ciphertext
		for (int i = 0; i < MESSAGE_SIZE; ++i)
		{
			ecurve_mult(r,pk,cipher_point[i]);
			ecurve_add(m_point[i],cipher_point[i]);
		}
		t2 = clock();

		printf("\n------ the plaintext ------\n\n");
		for (int i = 0; i < MESSAGE_SIZE; ++i)
		{
			epoint_get(m_point[i],x,y);
			otnum(x,stdout);
			otnum(y,stdout);
		}
		printf("\n------ the ciphertext ------\n\n");
		printf("M1:\n");
		epoint_get(r_point,x,y);
		otnum(x,stdout);
		otnum(y,stdout);
		printf("M2:\n");
		for (int i = 0; i < MESSAGE_SIZE; ++i)
		{
			epoint_get(cipher_point[i],x,y);
			otnum(x,stdout);
			otnum(y,stdout);
		}
		
	// Decryption
		t3 = clock();
		for (int i = 0; i < MESSAGE_SIZE; ++i)
		{
			ecurve_mult(sk,r_point,m_point[i]);
			ecurve_sub(m_point[i],cipher_point[i]);
		}
		t4 =clock();

		printf("\n------ the decryption ------\n\n");
		for (int i = 0; i < MESSAGE_SIZE; ++i)
		{
			epoint_get(cipher_point[i],x,y);
			otnum(x,stdout);
			otnum(y,stdout);
		}

		Enc += (double)(t2-t1);
		Dec += (double)(t4-t3);

		printf("\n=====================================");
		printf("\n             the cost (s)            ");
		printf("\n=====================================");
		printf("\nEnc:%lf",(double)((t2-t1))/CLOCKS_PER_SEC);
		printf("\nDec:%lf",(double)((t4-t3))/CLOCKS_PER_SEC);
	}

	printf("\n=====================================");
	printf("\n        the average cost (ms)        ");
	printf("\n=====================================");
	printf("\nEnc:%lf",Enc/ROUND);
	printf("\nDec:%lf",Dec/ROUND);
	
	return 0;
}