/* 
 * Copyright (c) hibiscus
 *
 * vehicle security
 *
 */

#ifndef _VS_BASE_H_
#define _VS_BASE_H_

#define VS_BASE_OK				0
#define VS_BASE_ERR				1
#define VS_BASE_SERVER_NULL		2
#define VS_BASE64_ERR			(-1)

#define VS_MSG_DATA_MAX_LEN		(64*1024)


#if 0
#define VS_COMM_DST_MAX_LEN	256 
struct vs_comm {
	int fd;
	unsigned char dst[VS_COMM_DST_MAX_LEN]; 
};
#endif

enum vs_evp_crypto_type {
	VS_EVP_ENCRYPT,
	VS_EVP_DECRYPT
};

/* 
 * dir create
 * @params
 *		c : dir path 
 * @return
 *		0 : create ok
 *      1 : create fail
*/
#define VS_BASE_DIR_MAX_LEN	256
uint8_t vs_create_dir(const char *path);

/* 
 * isspace check
 * @params
 *		c : character 
 * @return
 *		1 : is space
 *      0 : not space
*/
uint8_t vs_isspace(int c);

/* 
 * host byteorder to network
 * @params
 *		val : src data 
 * @return
 *		network byteorder data
*/
uint64_t vs_htonll(uint64_t val);

/* 
 * network byteorder to host
 * @params
 *		val : src data 
 * @return
 *		host byteorder data
*/
uint64_t vs_ntohll(uint64_t val);

/* 
 * check ip str is valid. support ipv4/ipv6
 * @params
 *		ip_str : ip str 
 * @return
 *		VS_BASE_OK: ip str is valid
 *		VS_BASE_ERR: ip str is invalid
*/
uint8_t vs_ip_addr_valid(const char *ip_str);

/* 
 * trans ip str to in_addr/in6_addr
 * @params
 *		family: AF_INET/AF_INET6 
 *		ip_str : ip str
 *		ipv4_addr: caller malloc. family is AF_INET, no NULL.
 *		ipv6_addr: caller malloc. family is AF_INET6, no NULL.
 * @return
 *		VS_BASE_OK: trans success
 *		VS_BASE_ERR: trans fail
*/
uint8_t vs_ip_addr_trans(uint8_t family, const char *ip_str,
							struct in_addr *ipv4_addr,
							struct in6_addr *ipv6_addr);

/* 
 * check str is all-number
 * @params
 *		str: str to check.
 * @return
 *		VS_BASE_OK: all char is digit
 *		VS_BASE_ERR: not all char is digit
*/
uint8_t vs_str_all_digit(const char *str);

/* 
 * openssl evp encrypt
 * @params
 *		nid: openssl algo nid or algo suite nid
 *		crypto_type: encrypt or decrypt 
 *		key : encrypt key, NULL for hash, caller make sure is ok
 *		input_text: clear text, cant NULL
 *		input_text_len: clear text len. cant <= 0
 *		output: cipher text, caller make sure enough. cant null
 *		output_len: cipher len. caller malloc the point. cant null
 * @return
 *		0: crypt ok
 *		not 0: crypt fail
*/
uint8_t vs_evp_cipher_crypto(uint16_t nid,
						enum vs_evp_crypto_type crypto_type,
						const uint8_t *key, 
						const uint8_t *input_text,
						int  input_text_len,
						uint8_t *output,
						int* output_len);

/* 
 * calc hash(digist) 
 * @params
 *		nid: algo id(see openssl obj_mac.h), > 0.
 *		data: data to hash, NO NULL. 
 *		data_len: data len, > 0.
 *		output: hash result mem, caller malloc, NO NULL.
 *		output_len: hash result bytes, caller malloc, NO NULL.
 * @return
 *		0: hash ok
 *		not 0: hash fail
*/
uint8_t vs_evp_digist(int nid,
						uint8_t *data,
						uint32_t data_len,
						uint8_t *output,
						uint32_t *output_len);

/* 
 * calc hmac
 * @params
 *		nid: algo id(see openssl obj_mac.h)
 *		key: key, NO NULL.
 *		key: key length, > 0.
 *		data: data to hash, NO NULL. 
 *		data_len: data len, > 0.
 *		output: hash result mem, caller malloc, NO NULL.
 *		output_len: hash result bytes, caller malloc, NO NULL.
 * @return
 *		0: hash ok
 *		not 0: hash fail
*/
uint8_t vs_hmac(int nid,
					uint8_t *key,
					uint32_t key_len,
					uint8_t *data,
					uint32_t data_len,
					uint8_t *output,
					uint32_t *output_len);

/* 
 * base64 encode
 * @params
 *		in_str: input data
 *		in_len: input data len
 *		out_str: transe result mem address, caller make sure is enough.
 *				 *******advise: out_str bytes = 1.5*in_len********
 * @return
 *		< 0: encode fail
 *		> 0: trans result(base64) len
*/
int vs_base64_encode(char *in_str, int in_len, char *out_str);

/* 
 * base64 decode
 * @params
 *		in_str: input data
 *		in_len: input data len
 *		out_str: transe result mem address, caller make sure is enough.
 *				 *******advise: out_str bytes = in_len********
 * @return
 *		< 0: encode fail
 *		> 0: trans result len
*/
int vs_base64_decode(char *in_str, int in_len, char *out_str);

/* 
 * create random string 
 * @params
 *		out: random string out addr, caller malloc it
 *		out_size: out's bytes
 *		out_len: create random string length, must less then out_size.
 * @return
 *		0: create ok
 *		not 0: create fail
*/
int vs_random_str(uint8_t *out, uint32_t out_size, uint32_t out_len);


/*
 * key generate
 *
 * @params
 *		key: output key
 *		seed1: seed
 *		seed2: seed 
 * */
void vs_key_generator(uint8_t key[16], uint32_t seed1, uint32_t seed2);
#endif
