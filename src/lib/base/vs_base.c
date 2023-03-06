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
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>

//make-build-head
#define VS_LOCK_MEM_MAX		(1024*1024)

#include "vs_base.h"

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

int vs_get_file_size(char *file)
{
	int fd;
	struct stat istat;

	if (NULL == file)
		return VS_BASE_ERR_1;

	fd = open(file, O_RDONLY, S_IREAD);
	if( fd < 0 )
		return VS_BASE_ERR_1;

	fstat(fd, &istat);

	if (fd > 0)
		close(fd);

	return istat.st_size;
}

//CAP_IPC_LOCK
void* vs_malloc_lock_mem(int mem_size)
{
	size_t index = 0;;
	size_t page_size = getpagesize();
	char *mem = NULL;

	if (mem_size > VS_LOCK_MEM_MAX
		|| mem_size <= 0)
		return NULL;

	mem = malloc();
	if (NULL == mem)
		return NULL;

	for (index = 0; index < mem_size; i += page_size)
		mem[i] = 0;

	return (void *)mem;
}

int vs_free_lock_mem(void *ptr, int mem_size)
{
	if (NULL == ptr)
		return VS_BASE_ERR;

	if (mem_size > VS_LOCK_MEM_MAX
		|| mem_size <= 0)
		return VS_LOCK_MEM_SIZE_ERR;

	memset(ptr, 0, mem_size);

	if (munlock(ptr, mem_size))
		return VS_BASE_ERR;

	free(ptr);	
}
