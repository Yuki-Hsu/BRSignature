/*
	A simple test of aes
	Usage:
	gcc -O2 aesencrypt.c miracl.a
*/

#include <stdio.h>
#include <time.h>
#include "miracl.h"

#define KEY_SIZE 16
#define BUFF_SIZE 16
#define ROUND 1000

double enc,dec;
clock_t t1,t2,t3,t4;

int main(int argc, char const *argv[])
{
	aes a;
	char key[KEY_SIZE] =  "1234567890abcde";	// 128 bits key
	char buff[BUFF_SIZE] = "aaaabbbbccccddd";	// 16 bytes input buffer
	
	printf("key:%s\n",key);
	printf("plaintext:%s\n",buff);
	for (int i = 0; i < BUFF_SIZE; ++i)
	{
		printf("%5d",buff[i]);
	}
	printf("\n");

	for (int i = 0; i < ROUND; ++i)
	{
	// encrytion
		t1 = clock();
		aes_init(&a,MR_ECB,16,key,NULL);	// in MR_ECB mode, the initialisation vector can be NULL
		aes_encrypt(&a,buff);
		aes_end(&a);
		t2 = clock();

		printf("ciphertext:%s\n",buff);
		for (int i = 0; i < BUFF_SIZE; ++i)
		{
			printf("%5d",buff[i]);
		}
		printf("\n");

	// decrytion
		t3 = clock();
		aes_init(&a,MR_ECB,16,key,NULL);	// in MR_ECB mode, the initialisation vector can be NULL
		aes_decrypt(&a,buff);
		aes_end(&a);
		t4 = clock();

		printf("plaintext:%s\n",buff);
		for (int i = 0; i < BUFF_SIZE; ++i)
		{
			printf("%5d",buff[i]);
		}
		printf("\n");

		enc += (double)(t2-t1);
		dec += (double)(t4-t3);
	}

	printf("\n=====================================");
	printf("\n        the average cost (ms)        ");
	printf("\n=====================================");
	printf("\nEnc:%lf",enc/ROUND);
	printf("\nDec:%lf",dec/ROUND);
	return 0;
}