#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "comm.h"
#include "cfg_parse.h"

static struct vs_socket vs_client;

char* vs_file_content(char *path,
                    char *file_name,
                    unsigned int max_size,
                    unsigned char crypt,
                    unsigned char mlock,
                    int *fsize)
{
	FILE *fp = NULL;
	int file_size = 0;
	char *buff = NULL;
	char *buff1 = NULL;
    char file[1024] = {0};
    size_t i = 0, page_size = 0;
    uint8_t iv_or_nonce[16] = {0xa1, 0x02, 0x34, 0x93, 0x2f, 0x8e, 0x02, 0x18,
                                0x6f, 0xf1, 0x4d, 0x7c, 0xfb, 0xaa, 0xf2, 0xfe};

	if (NULL == path
        || NULL == file_name
        || NULL == fsize)
		return NULL;

    if ((strlen(path) + strlen(file_name)) > sizeof(file))
        return NULL;

    //defualt 1K
    if (0 == max_size)
        max_size = 1024;

    snprintf(file, sizeof(file), "%s/%s", path, file_name);
	
	file_size = vs_get_file_size(file);
	if (file_size < 0 || file_size > max_size)
		return NULL;

    fsize = file_size;
	fp = fopen(file, "r");
	if (NULL == fp)
		return NULL;

    buff = malloc(file_size);
    if (NULL == buff)
        goto out1;

    i = fread(buff, 1, file_size, fp);
    if (i != file_size)
        goto out2;

    if (0 == crypt) {
        //read success
        return buff; 
    }

    buff1 = (char *)malloc(file_size);
    if (NULL == buff1)
        goto out2;

    if (mlock) {
        if (mlock((void *)buff1, file_size))
            goto out3;
    
        //lock mem, right now. 
        page_size = getpagesize();
        for (i = 0; i < file_size; i++)
            buff1[i] = 0;
    }

    aes_whitebox_decrypt_ctr(iv_or_nonce, buff, file_size, buff1);    
    
    free(buff);

	return buff1;

out3:
    free(buff1);
    buff1 = NULL;

out2:
    free(buff);
    buff = NULL;

out1:
    fclose(fp);
    fp = NULL;

    return NULL;
}

int vs_mbedtls_init()
{
	int ret = 0;
    int content_len = 0;
    char *content = NULL;
	size_t client_cert_name_len = 0;
	struct vs_ep_cfg *cfg = vs_ep_cfg_get();

	mbedtls_net_init(&(vs_client->ctx.net_ctx));
	mbedtls_ssl_init(&(vs_client->ctx.ssl_ctx));
	mbedtls_ssl_config_init(&(vs_client->ctx.ssl_cfg));
	mbedtls_ctr_drbg_init(&(vs_client->ctx.drbg_ctx));
	mbedtls_x509_crt_init(&(vs_client->ctx.x509_ca_crt));
	mbedtls_x509_crt_init(&(vs_client->ctx.x509_client_crt));
	mbedtls_pk_init(&(vs_client->ctx.pkey));
	mbedtls_entropy_init(&(vs_client->ctx.etpy_ctx));

    content = vs_file_content(cfg->pki_file_path, cfg->ca_client,
                                10240, 0, 0, &content_len);
    if (NULL == content || content_len <= 0)
        return VS_ERR;
	ret = mbedtls_x509_crt_parse(&(vs_client->ctx.x509_ca_crt),
					(const unsigned char *)(content),
					content_len);
    free(content);
	if (ret)
		return VS_ERR;

	client_cert_name_len =  strlen(cfg->cert_client);
	if (client_cert_name_len > 0) {
        content = vs_file_content(cfg->pki_file_path,
                                cfg->cert_client,
                                10240, 0, 0,
                                &content_len);
        if (NULL == content || content_len <= 0)
            return VS_ERR;
		ret = mbedtls_x509_crt_parse(&vs_client->x509_client_crt,
					(const unsigned char *)(content),
					content_len);
		if (ret)
			return VS_ERR;
		
        content = vs_file_content(cfg->pki_file_path,
                                cfg->pkey_client,
                                4096, 0, 0,
                                &content_len);
        if (NULL == content || content_len <= 0)
            return VS_ERR;
		ret = mbedtls_pk_parse_key(&(vs_client->ctx.pkey),
					(const unsigned char *)(content),
					content_len,
					NULL, 0,
					mbedtls_ctr_drbg_random, NULL);
		if (ret)
			return VS_ERR;

		ret = mbedtls_ssl_conf_own_cert(&(vs_client->ctx.ssl_cfg),
					&(vs_client->ctx.x509_client_crt),
					&(vs_client->ctx.pkey));
		if (ret)
			return VS_ERR;
	}

	ret = mbedtls_ctr_drbg_seed(&(vs_client->ctx.drbg_ctx),
					mbedtls_entropy_func,
					&(vs_client->ctx.etpy_ctx),
					(const unsigned char *)("mbedtls_clt"),
					strlen("mbedtls_clt"));
	if (ret)
		return VS_ERR;

	ret = mbedtls_ssl_config_defaults(&(vs_client->ctx.ssl_cfg),
					MBEDTLS_SSL_IS_CLIENT,
					MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret)
		return VS_ERR;

	mbedtls_ssl_conf_cert_profile(&(vs_client->ctx.ssl_cfg), &x509_crt_profile);
	mbedtls_ssl_conf_sig_hashes(&(vs_client->ctx.ssl_cfg), mbedtls_ssl_sig_hashes);
	mbedtls_ssl_conf_authmode(&(vs_client->ctx.ssl_cfg), MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_rng(&(vs_client->ctx.ssl_cfg), mbedtls_ctr_drbg_random, &(vs_client->ctx.drbgctx));
	mbedtls_ssl_conf_ca_chain(&(vs_client->ctx.ssl_cfg), &(vs_client->ctx.x509_ca_crt), NULL);

	ret = mbedtls_ssl_setup(&(vs_client->ctx.ssl_ctx), &(vs_client->ctx.ssl_cfg));
	if (ret)
		return VS_ERR;

	ret = mbedtls_ssl_set_hostname(&(vs_client->ctx.ssl_ctx), (const char *)("vs_tls"));
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
