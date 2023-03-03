/* 
 * Copyright (c) hibiscus
 *
 * vehicle security
 *
 */

#ifndef _VS_BASE_H_
#define _VS_BASE_H_

#include <stdint.h>
#include <arpa/inet.h>
#include <pthread.h>

#define VS_BASE_OK				0
#define VS_BASE_ERR				1
#define VS_BASE_SERVER_NULL		2
#define VS_LOCK_MEM_SIZE_ERR	3
#define VS_BASE64_ERR			(-1)
#define VS_BASE_ERR_1			(-1)

#define VS_MSG_DATA_MAX_LEN		(64*1024)

#define VS_COMM_PORT_MAX_LEN	8
#define VS_COMM_ADDR_MAX_LEN	64
#define VS_COMM_OFFLOG_PATH_MAX_LEN	256

enum vs_comm_sock_add_type {
	VS_SOCK_ADDR_IP,
	VS_SOCK_ADDR_HOST
};

enum vs_comm_sock_type {
	VS_COMM_SOCK_CLIENT,
	VS_COMM_SOCK_SERVER
};

struct vs_offline_log {
	FILE *fd;
	pthread_mutex_t mutex;
	uint32_t max_byte_total;
	uint32_t file_max_byte_per;
	uint8_t path[VS_COMM_OFFLOG_PATH_MAX_LEN];
};


//client send heartbeat to server
struct vs_comm_manager {
	int fd;
	pthread_mutex_t mutex;
	
	uint8_t sock_type;
	uint8_t addr_type;
	//addr for ip/host
	uint8_t sock_addr[VS_COMM_ADDR_MAX_LEN]; 
	uint8_t sock_port[VS_COMM_PORT_MAX_LEN];
	uint8_t *send_buff;
	uint16_t send_buff_size;
	uint16_t send_len;	
	uint8_t *rcv_buff;
	uint16_t rcv_buff_size;
	uint16_t rcv_len;

	uint8_t client_max;

	//us
	uint32_t yield_time;	
	uint16_t heartbeat_cycle;
	uint8_t heartbeat_over_times;

	struct vs_offline_log offline_log;	
};

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

/*
 * get file size
 *
 * @params
 *		file: filename,full path
 * @return
 * 		return file size
 * 		< 0, fail
 * */
int vs_get_file_size(char *file);

/*
 * malloc lock mem
 *
 * @params
 *		mem_size: size
 * @return
 * 		NULL: malloc fail
 * 		NOT NULLL: malloc success
 * */
void* vs_malloc_lock_mem(int mem_size);

/*
 * free lock mem
 *
 * @params
 *		ptr: mem point
 *		mem_size: mem size
 * @return
 * 		0: free success
 * 		NOT 0: free fail
 * */
int vs_free_lock_mem(void *ptr, int mem_size);
#endif
