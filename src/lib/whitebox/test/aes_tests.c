// Copyright 2019 AES WBC Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "aunit.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <math.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <dirent.h>

#include "aes.h"
#include "aes_whitebox.h"

#define BUF_SZ 64

void (*encrypt)(const uint8_t iv[16], const uint8_t* m,
      size_t len, uint8_t* c) = NULL;
void (*decrypt)(const uint8_t iv[16], const uint8_t* m,
      size_t len, uint8_t* c) = NULL;

static void err_quit(const char *fmt, ...) {
  va_list ap;
  char buf[1024];

  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  strcat(buf, "\n");
  fputs(buf, stderr);
  fflush(stderr);
  va_end(ap);

  exit(1);
}

#if 0
static void read_hex(const char *in, uint8_t* v, size_t size, const char* param_name) {
  if (strlen(in) != size << 1) {
    err_quit("Invalid param %s (got %d, expected %d)",
        param_name, strlen(in), size << 1);
  }
  for (size_t i = 0; i < size; i++) {
    sscanf(in + i * 2, "%2hhx", v + i);
  }
}
#endif

void syntax(const char* program_name) {
  err_quit("Syntax: %s <cfb|ofb|ctr>"
      " <hex-plain>"
      " <hex-ir-or-nonce>"
      " <hex-cipher>", program_name);
}


void usage()
{
    fprintf(stdout, "Usage: wbcrypt [-e] | [-d] -i inputfile -o output\n");
    fprintf(stdout, "   -e  encrypt\n");
    fprintf(stdout, "   -d 	decrypt\n");
	fprintf(stdout, "   -i  input file\n");
    fprintf(stdout, "   -o 	output file\n");
 
    _exit(0);
}
 
int get_file_size(char *filename)
{
	int fd;
	struct stat istat;
	
	fd = open(filename, O_RDONLY, S_IREAD);
	if( fd < 0 ) {
		printf("get_file_size: Unable to open file\n");
		return -1;
	} 
	
	fstat(fd, &istat);

	if (fd > 0)
		close(fd);

	return istat.st_size;
}


int wb_crypt_file(char *infile, char *outfile)
{
	int write_cn = 0;
	int read_cn = 0;
	int file_sz = 0;
	int ifd = 0, ofd = 0;
	unsigned char inbuf[BUF_SZ] = {0};
	unsigned char outbuf[BUF_SZ] = {0};
	uint8_t iv_or_nonce[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8};

	ifd = open(infile, O_RDONLY, S_IREAD);
	if (ifd < 0) {
		printf("open input file %s error\r\n", infile);
		return -1;
	}

	ofd = creat(outfile, S_IRUSR | S_IWUSR);
	if(ofd < 0) {
		printf("Error: Unable to create output file %s\n", outfile);
		close(ifd);
		return 0;
	}

	file_sz = get_file_size(infile);
	printf("[%s, %d] file_sz = %d\n", __func__, __LINE__, file_sz);
	if (file_sz <= 0) {
		printf("get input file size error\r\n");
		return 1;
	}

	int xxx = 0;
	while (file_sz > 0) {

		memset(inbuf, 0, BUF_SZ);
		memset(outbuf, 0, BUF_SZ);
		
		
		file_sz -= BUF_SZ;
			
		read_cn = read(ifd, (void *)inbuf, BUF_SZ);
		if(read_cn <= 0) {
			printf("read input file error\r\n");
			goto error;
		}
	  
    	printf("[%s, %d] read_cn = %d\n", __func__, __LINE__, read_cn);
	  	encrypt = &aes_whitebox_encrypt_ctr;

		//wb_aes_crypt(inbuf, outbuf, 0);
		(*encrypt)(iv_or_nonce, inbuf, read_cn, outbuf);

		printf("crypt[%s, %d]\n", __func__, __LINE__);
		for (xxx = 0; xxx < BUF_SZ; xxx++)
			printf("%x ", outbuf[xxx]);
		printf("\n");
		printf("crypt end[%s, %d]\n", __func__, __LINE__);

		write_cn = write(ofd, outbuf, read_cn);
		if( write_cn < 0) {
			printf("write output file error\n");
			goto error;
		}
		
	}

	close(ifd);
	close(ofd);
	return 0;

error:	
	close(ifd);
	close(ofd);
	return -1;
}

int wb_decrypt_file(char *infile, char *outfile)
{
	int write_cn = 0;
	int read_cn = 0;
	int file_sz = 0;
	int ifd = 0, ofd = 0;
	unsigned char inbuf[BUF_SZ] = {0};
	unsigned char outbuf[BUF_SZ] = {0};
  	uint8_t iv_or_nonce[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8};

	ifd = open(infile, O_RDONLY, S_IREAD);
	if (ifd < 0) {
		printf("open input file %s error\r\n", infile);
		return -1;
	}

	ofd = creat(outfile, S_IRUSR | S_IWUSR);
	if(ofd < 0) {
		printf("Error: Unable to create output file %s\n", outfile);
		close(ifd);
		return 0;
	}
	
	file_sz = get_file_size(infile);
	if (file_sz <= 0) {
		printf("get input file size error\r\n");
		return 1;
	}

	int xxx = 0;
	while (file_sz > 0) {

		memset(inbuf, 0, BUF_SZ);
		memset(outbuf, 0, BUF_SZ);
		
		file_sz -= BUF_SZ;
		
		read_cn = read(ifd, (void *)inbuf, BUF_SZ);
		if(read_cn <= 0) {
			printf("read input file error, read_cn = %d\r\n", read_cn);
			goto error;
		}
		
		printf("crypt [%s, %d]\n", __func__, __LINE__);	
		for (xxx = 0; xxx < read_cn; xxx++)
			printf("%x ", inbuf[xxx]);
		printf("\n");
		printf("crypt end[%s, %d]\n", __func__, __LINE__);	

    decrypt = &aes_whitebox_decrypt_ctr;
		//wb_aes_crypt(inbuf, outbuf, 1);
    (*decrypt)(iv_or_nonce, inbuf, read_cn, outbuf);

		for (xxx = 0; xxx < BUF_SZ; xxx++)
			printf("%x ", outbuf[xxx]);
		printf("\n");

	

		write_cn = write(ofd, outbuf, read_cn);
		if( write_cn < 0) {
			printf("write output file error\n");
			goto error;
		}
	}

	close(ifd);
	close(ofd);
	return 0;

error:	
	close(ifd);
	close(ofd);
	return -1;
}

au_main

{
  int ch;
	opterr = 0;
	int encypt = 0;
	char *infile = NULL;
	char *outfile = NULL;
	
	srandom(1234);	
	while ((ch = getopt(argc, argv, "dei:o:")) != -1)  {  
		switch(ch)  {  
			case 'e': 
				encypt = 1;
				break;  
			case 'd': 
				encypt = 0;
				break; 
			case 'i':
				infile = optarg;
				break; 
			case 'o': 
				outfile = optarg;
				break; 
			default:  
				usage();  
		}  
	}
	
	if (optind > argc)
        usage();
	
	if (!infile || !outfile)
        usage();

	if (encypt)
		wb_crypt_file(infile, outfile);
	else
		wb_decrypt_file(infile, outfile);

	return 0;	
}

au_endmain
