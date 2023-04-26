#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "comm.h"
#include "cfg_parse.h"

static struct vs_socket vs_client;

int vs_crypt_file_get(char *path, unsigned int max_size, unsigned char mlock_flag)
{
	FILE *fp = NULL;
	int file_size = 0;
	char *buff = NULL;

	if (NULL == path)
		return VS_ERR;
	
	file_size = vs_get_file_size(path);
	if (file_size < 0 || file_size > max_size)
		return VS_ERR;

	fp = fopen(file, "r");
	if (NULL == fp)
		return VS_ERR;



	return VS_OK;
}

int vs_mbedtls_init()
{
	struct vs_ep_cfg *cfg = vs_ep_cfg_get();

	mbedtls_net_init(&vs_client->ctx.netctx);
	mbedtls_ssl_init(&vs_client->ctx.sslctx);
	mbedtls_ssl_config_init(&vs_client->ctx.sslcfg);
	mbedtls_ctr_drbg_init(&vs_client->ctx.drbgctx);
	mbedtls_x509_crt_init(&vs_client->ctx.x509cacrt);
	mbedtls_x509_crt_init(&vs_client->ctx.x509clicrt);
	mbedtls_pk_init(&vs_client->ctx.pkey);
	mbedtls_entropy_init(&vs_client->ctx.etpyctx);


}

int communication_init()
{
	struct vs_ep_cfg *cfg = vs_ep_cfg_get();

	if (NULL == cfg)
		return VS_ERR;

	if (VS_OK != vs_mbedtls_init())
		return VS_ERR;

	return VS_OK;	
}
