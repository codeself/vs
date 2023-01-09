/* 
 * Copyright (c) hibiscus
 *
 * vehicle security
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/ossl_typ.h>

#include "vs_base.h"

extern int a;

uint8_t vs_create_dir(const char *path)
{
	size_t i = 0;
	size_t path_len = 0;
	char path_cache[VS_BASE_DIR_MAX_LEN] = {0};

	if (NULL == path)
		return VS_BASE_ERR;

	path_len = strlen(path);
	/* maybe append "/" */
	if (path_len >= (VS_BASE_DIR_MAX_LEN - 1))
		return VS_BASE_ERR;

	strncpy(path_cache, path, VS_BASE_DIR_MAX_LEN);
	if ('/' != path_cache[path_len-1]) {
		path_cache[path_len] = '/';
		path_len++;
	}

	/* skip first char, maybe "/" */
	for (i = 1; i < path_len; i++ ) {
		if ('/' != path_cache[i])
			continue;

		path_cache[i] = 0;
		/* path exist */
		if (0 == access(path_cache, F_OK)) {
			path_cache[i] = '/';
			continue;
		}

		if (mkdir(path_cache, 0660))
			return VS_BASE_ERR;

		path_cache[i] = '/';
	}

	return VS_BASE_OK;
}

uint8_t vs_isspace(int c)
{
	if (c == ' ' 
		|| c == '\f'
		|| c == '\n'
		|| c == '\r'
		|| c == '\t'
		|| c == '\v')
		return 1;

	return 0;
}


uint64_t vs_htonll(uint64_t val)
{
    return (((uint64_t) htonl(val)) << 32) + htonl(val >> 32);
}

uint64_t vs_ntohll(uint64_t val)
{
    return (((uint64_t) ntohl(val)) << 32) + ntohl(val >> 32);
}

uint8_t vs_ip_addr_valid(const char *ip_str)
{
	int ret = 0;
	unsigned char buf[sizeof(struct in6_addr)] = {0};

	if (NULL == ip_str)	
		return VS_BASE_ERR;

	ret = inet_pton(AF_INET, ip_str, buf);
	if (1 != ret) {
		ret = inet_pton(AF_INET6, ip_str, buf);
		if (1 != ret)
			return VS_BASE_ERR;
	}

	return VS_BASE_OK;
}

uint8_t vs_ip_addr_trans(uint8_t family, const char *ip_str,
							struct in_addr *ipv4_addr,
							struct in6_addr *ipv6_addr)
{
	int ret = 0;

	if (NULL == ip_str)
		return VS_BASE_ERR;

	if (AF_INET == family) {
		if (NULL == ipv4_addr)
			return VS_BASE_ERR;

		ret = inet_pton(AF_INET, ip_str, ipv4_addr);
		if (1 != ret)
			return VS_BASE_ERR;

	} else if (AF_INET6 == family) {
		if (NULL == ipv6_addr)
			return VS_BASE_ERR;

		ret = inet_pton(AF_INET6, ip_str, ipv6_addr);
		if (1 != ret)
			return VS_BASE_ERR;

	} else {
		return VS_BASE_ERR;
	}

	return VS_BASE_OK;
}

uint8_t vs_str_all_digit(const char *str)
{
	size_t i = 0;
	size_t str_len = 0;
	char *cache = (char *)str;

	if (NULL == str)
		return VS_BASE_ERR;

	str_len = strlen(str);
	for (i = 0; i < str_len; i++) {
		if (0 == isdigit(*cache))
			return VS_BASE_ERR;

		cache++;
	}

	return VS_BASE_OK;
}

/* caller make sure output mem */
uint8_t vs_evp_cipher_crypto(uint16_t nid,
						enum vs_evp_crypto_type crypto_type,
						const uint8_t *key, 
						const uint8_t *input_text,
						int  input_text_len,
						uint8_t *output,
						int* output_len)
{
	int out_len = 0;
	int out_len_fi = 0;
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *cipher = NULL;

	ctx = EVP_CIPHER_CTX_new();

	if (NULL == ctx
		|| NULL == input_text
		|| NULL == output
		|| NULL == output_len)
		return VS_BASE_ERR;

	if (input_text_len <= 0) {
		EVP_CIPHER_CTX_free(ctx);
		return VS_BASE_ERR;
	}
	
	OpenSSL_add_all_ciphers();
	cipher = EVP_get_cipherbynid((int)nid);
	if (NULL == cipher) {
		EVP_CIPHER_CTX_free(ctx);
		return VS_BASE_ERR;
	}

	EVP_CIPHER_CTX_init(ctx);
	
	if (VS_EVP_ENCRYPT == crypto_type) {
		EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);
		EVP_EncryptUpdate(ctx, output, &out_len, input_text, input_text_len);
		EVP_EncryptFinal_ex(ctx, (output + out_len), &out_len_fi);
	} else {
		EVP_DecryptInit_ex(ctx, cipher, NULL, key, NULL);
		EVP_DecryptUpdate(ctx, output, &out_len, input_text, input_text_len);
		EVP_DecryptFinal_ex(ctx, (output + out_len), &out_len_fi);
	}

	*output_len = out_len + out_len_fi;

	EVP_CIPHER_CTX_free(ctx);

	return VS_BASE_OK;
}

uint8_t vs_evp_digist(int nid, uint8_t *data, uint32_t data_len,
							uint8_t *output, uint32_t *output_len)
{
	EVP_MD_CTX *mdctx = NULL;
	const EVP_MD *md = NULL;
	
	if (nid <= 0
		|| NULL == data
		|| NULL == output
		|| NULL == output_len)
		return VS_BASE_ERR;

	mdctx = EVP_MD_CTX_new();
	if (NULL == mdctx)
		return VS_BASE_ERR;

	OpenSSL_add_all_digests();

	md = EVP_get_digestbynid(nid);
	if(!md)
		return VS_BASE_ERR;
	
	EVP_MD_CTX_init(mdctx);
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, (const void *)data, data_len);
	EVP_DigestFinal_ex(mdctx, (unsigned char *)output, (unsigned int *)output_len);
	
	EVP_MD_CTX_reset(mdctx);	

	return VS_BASE_OK;
}

uint8_t vs_hmac(int nid, uint8_t *key, uint32_t key_len, uint8_t *data, uint32_t data_len,
							uint8_t *output, uint32_t *output_len)
{
	const EVP_MD *md = NULL;

	if (nid <= 0
		|| NULL == key
		|| 0 == key_len 
		|| NULL == data
		|| 0 == data_len
		|| NULL == output
		|| NULL == output_len)
		return VS_BASE_ERR;

	OpenSSL_add_all_digests();

	md = EVP_get_digestbynid(nid);
	if(!md)
		return VS_BASE_ERR;

	if (NULL == HMAC(md, (const void *)key, (int)key_len,
						(const unsigned char *)data, data_len,
						(unsigned char *)output, (unsigned int *)output_len))
		return VS_BASE_ERR;

	return VS_BASE_OK;
}

/* advise: out_str mem = 1.5*in_str */
int vs_base64_encode(char *in_str, int in_len, char *out_str)
{
    BIO *b64 = NULL, *bio = NULL;
    BUF_MEM *bptr = NULL;
    size_t size = 0;

    if (in_str == NULL || out_str == NULL)
        return VS_BASE64_ERR;
    
    b64 = BIO_new(BIO_f_base64());
	if (NULL == b64)
		return VS_BASE64_ERR;

    bio = BIO_new(BIO_s_mem());
	if (NULL == bio) {
		BIO_free(b64);
		return VS_BASE64_ERR;
	}

    bio = BIO_push(b64, bio);
    
    if (BIO_write(bio, in_str, in_len) < 0) {
		/* bio is push to b64 */
		BIO_free_all(b64);
		return VS_BASE64_ERR;
	}
    (void)BIO_flush(bio);
    
    BIO_get_mem_ptr(bio, &bptr);
    memcpy((void *)out_str, (const void *)bptr->data, bptr->length);
    out_str[bptr->length] = '\0';
    size = bptr->length;
    
    BIO_free_all(b64);
    return size;
}       

/* advise: out_str mem = in_str */
int vs_base64_decode(char *in_str, int in_len, char *out_str)
{   
    BIO *b64 = NULL, *bio = NULL;
    int size = 0;
    
    if (in_str == NULL || out_str == NULL)
        return -1;
    
    b64 = BIO_new(BIO_f_base64());
	if (NULL == b64)
		return VS_BASE64_ERR;
    
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    bio = BIO_new_mem_buf(in_str, in_len);
	if (NULL == bio) {
		BIO_free(b64);
		return VS_BASE64_ERR;
	}

    bio = BIO_push(b64, bio);

    size = BIO_read(bio, out_str, in_len);
    out_str[size] = '\0';
 
    BIO_free_all(b64);
    return size;
}

int vs_random_str(uint8_t *out, uint32_t out_size, uint32_t out_len)
{
	int i = 0;
	int rand_num = 0;

	if (out_len > out_size)
		return VS_BASE_ERR;

	if (NULL == out)
		return VS_BASE_ERR;
	
	srand((unsigned)time(NULL));	
	for (i = 0; i < (int)out_len; i++) {
		rand_num = rand() % 3;
		
		if (0 == rand_num)
			out[i] = 'A' + rand() % 26;
		else if (1 == rand_num)
			out[i] = 'a' + rand() % 26;
		else if (2 == rand_num)
			out[i] = '0' + rand() % 10;
		else
			out[i] = '=';	
	}

	return VS_BASE_OK;
}
