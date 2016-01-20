#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/md5.h>
#include <string.h>
#include "xcrypt.h"
#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif
#define MAX_FILE_LENGTH 1024
#define MD5_KEY_LENTH 16

struct input
{

char *infile;
char *outfile;
unsigned char *keybuf;
unsigned int keylen;
int flags;
};

int main(int argc,  char *argv[])
{
	
	
	int c; 
	int eflag=0, pflag=0;
	int err=0;
	struct input *in ;
	int pass_len;	
	unsigned char *str;
	extern char *optarg;
	extern int optind;
	
    
    in = malloc(sizeof(struct input));
	if (!in) {
		printf("[main]: malloc FAILED");
    	errno = -ENOMEM;
		goto out_ok;
  	}
	in->keybuf=malloc(MD5_DIGEST_LENGTH);
	if (!in->keybuf) {
		printf("[main]: malloc FAILED");
    	errno = -ENOMEM;
		goto out_3;
  	}
	
	
	while ((c = getopt(argc, argv, "p:edh")) != -1)
		switch (c) {
		case 'e':
			eflag = 1;
			in->flags=1;
			break;
		case 'd':
			eflag = 1;
			in->flags=0;
			break;
		case 'p':
			pflag = 1;
			str=(unsigned char *)optarg;
			break;
		case 'h':
			printf("-p: password, -e/-d for encryption/decryption,\n input and output file names.\n");
			break;
		case '?':
			err = 1;
			break;
		}
	if (eflag == 0) {	
		printf("%s: missing -e/-d option\n", argv[0]);
		err=-1;
		goto out;
	} 
	else if (pflag == 0) {	
		printf("%s: missing -p option\n", argv[0]);
		err=-1;
		goto out;
		
	} else if ((optind+2) > argc) {	
		/* need at least one argument (change +1 to +2 for two, etc. as needeed) */

		printf("optind = %d, argc=%d\n", optind, argc);
		printf("%s: missing name\n", argv[0]);
		goto out;
		
	} else if (err) {
		err=-1;
		goto out;
		
	}
	
	
	if (optind < argc)	{/* these are the arguments after the command-line options */
		in->infile=argv[optind];
		in->outfile=argv[optind+1];
	} else {
		printf("Input and output filename not specified, XCIPHER FAILED\n");
		err=-1;
		goto out;
	}
	
	pass_len=strlen((char *)str);
	
	
	MD5(str,pass_len,in->keybuf);
	in->keylen=MD5_KEY_LENTH;

	err = syscall(__NR_xcrypt, (void *)in);
	if (err == 0)
		printf("syscall returned success %d\n", err);
	else
		printf("syscall returned failiure %d (errno=%d)\n", err, errno);

	out:
	if(in->keybuf)
	free(in->keybuf);
	out_3:
	if(in)
	free(in);
	out_ok:
	exit(err);
}
