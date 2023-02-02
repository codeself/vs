#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <dirent.h>

#define BUF_SZ  16

extern void wb_aes_encrypt(char *in, char *out);
extern void wb_aes_decrypt(char *in, char *out);

void usage()
{
    fprintf(stdout, "Usage: wbcrypt [-e] | [-d] -i inputfile -o outputfile\n");
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
	int ret = 0;
	int write_cn = 0;
	int read_cn = 0;
	int file_sz = 0;
	int ifd = 0, ofd = 0;
	int padding_size = 0, i = 0, j = 0;
	unsigned char inbuf[BUF_SZ] = {0};
	unsigned char outbuf[BUF_SZ] = {0};

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

	while (file_sz >= 0) {

		memset(inbuf, 0, BUF_SZ);
		memset(outbuf, 0, BUF_SZ);
		
		if (file_sz > 0) {
			file_sz -= BUF_SZ;
			
			read_cn = read(ifd, (void *)inbuf, BUF_SZ);
			if(read_cn <= 0) {
				printf("read input file error\r\n");
				goto error;
			}
			
			//pkcs7 padding	
			if (read_cn < BUF_SZ) {
				padding_size = BUF_SZ - read_cn;
				j = read_cn;
				for (i = 0; i < padding_size && j < BUF_SZ; i++) {
					inbuf[j] = padding_size;
					j++;
				}
			}
		}

		//pkcs7 padding	
		//plaint-text % 16 == 0, padding 16 bytes 0x10
		if (file_sz == 0) {
			memset(inbuf, 0x10, BUF_SZ);	
		}
		
		wb_aes_encrypt(inbuf, outbuf);
		
		write_cn = write(ofd, outbuf, BUF_SZ);
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
	int ret = 0;
	int write_cn = 0;
	int data_len = 0;
	int read_cn = 0;
	int file_sz = 0;
	int ifd = 0, ofd = 0;
	int padding_size = 0, i = 0, j = 0;
	unsigned char inbuf[BUF_SZ] = {0};
	unsigned char outbuf[BUF_SZ] = {0};

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

	while (file_sz > 0) {

		memset(inbuf, 0, BUF_SZ);
		memset(outbuf, 0, BUF_SZ);
		
		file_sz -= BUF_SZ;
		
		read_cn = read(ifd, (void *)inbuf, BUF_SZ);
		if(read_cn <= 0) {
			printf("read input file error, read_cn = %d\r\n", read_cn);
			goto error;
		}
			
		wb_aes_decrypt(inbuf, outbuf);
	
		int xxx = 0;
		for (xxx = 0; xxx < BUF_SZ; xxx++)
			printf("%x ", outbuf[xxx]);
		printf("\n");

		data_len = BUF_SZ;	
		//padding data in last data block
		if (file_sz == 0) {
			padding_size = outbuf[BUF_SZ - 1];
			printf("padding_size = %d\n", padding_size);
			if (padding_size > BUF_SZ) {
				printf("decrypt padding(error) last byte is %d\r\n", padding_size);
				goto error;
			}

			//plaint text len % 16 == 0
			data_len = BUF_SZ - padding_size;
			if (0 == data_len)
				break;
		}

		write_cn = write(ofd, outbuf, data_len);
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

//pkcs7 padding
int main(int argc, char *argv[])  
{
	int ch;
	opterr = 0;
	int encypt = 0;
	char *infile = NULL;
	char *outfile = NULL;
	
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
