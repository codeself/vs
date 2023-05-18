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
	int ret = 0;
	size_t client_cert_len = 0;
	struct vs_ep_cfg *cfg = vs_ep_cfg_get();

	mbedtls_net_init(&vs_client->ctx.netctx);
	mbedtls_ssl_init(&vs_client->ctx.sslctx);
	mbedtls_ssl_config_init(&vs_client->ctx.sslcfg);
	mbedtls_ctr_drbg_init(&vs_client->ctx.drbgctx);
	mbedtls_x509_crt_init(&vs_client->ctx.x509cacrt);
	mbedtls_x509_crt_init(&vs_client->ctx.x509clicrt);
	mbedtls_pk_init(&vs_client->ctx.pkey);
	mbedtls_entropy_init(&vs_client->ctx.etpyctx);

	ret = mbedtls_x509_crt_parse(&vs_client->x509cacrt,
					(const unsigned char *)(cfg->ca_client),
					strlen(cfg->ca_client));
	if (ret)
		return VS_ERR;

	client_cert_len =  strlen(cfg->cert_client);
	if (client_cert_len > 0) {
		ret = mbedtls_x509_crt_parse(&vs_client->x509clicrt,
					(const unsigned char *)(cfg->cert_client),
					client_cert_len);
		if (ret)
			return VS_ERR;
		
		ret = mbedtls_pk_parse_key(&vs_client->pkey,
					(const unsigned char *)(cfg->pkey_client),
					strlen(cfg->pkey_client),
					NULL, 0,
					mbedtls_ctr_drbg_random, NULL);
		if (ret)
			return VS_ERR;

		ret = mbedtls_ssl_conf_own_cert(&vs_client->sslcfg,
					&vs_client->x509clicrt,
					&vs_client->pkey);
		if (ret)
			return VS_ERR;
	}

	ret = mbedtls_ctr_drbg_seed(&vs_client->drbgctx,
					mbedtls_entropy_func,
					&vs_client->etpyctx,
					(const unsigned char *)("mbedtls_clt"),
					strlen("mbedtls_clt"));
	if (ret)
		return VS_ERR;

	ret = mbedtls_ssl_config_defaults(&vs_client->sslcfg,
					MBEDTLS_SSL_IS_CLIENT,
					MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret)
		return VS_ERR;

	mbedtls_ssl_conf_cert_profile(&vs_client->sslcfg, &x509_crt_profile);
	mbedtls_ssl_conf_sig_hashes(&vs_client->sslcfg, mbedtls_ssl_sig_hashes);
	mbedtls_ssl_conf_authmode(&vs_client->sslcfg, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_rng(&vs_client->sslcfg, mbedtls_ctr_drbg_random, &vs_client->drbgctx);
	mbedtls_ssl_conf_ca_chain(&vs_client->sslcfg, &vs_client->x509cacrt, NULL);

	ret = mbedtls_ssl_setup(&vs_client->sslctx, &vs_client->sslcfg);
	if (ret)
		return VS_ERR;

	ret = mbedtls_ssl_set_hostname(&vs_client->sslctx, (const char *)("vs_tls"));
	if (ret)
		return VS_ERR;

	return VS_OK;
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
