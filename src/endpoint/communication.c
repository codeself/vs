#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "comm.h"
#include "cfg_parse.h"
#include "vs_queue_mng.h"
#include "data_process.h"

static uint32_t send_data_len_total = 0;
static struct vs_socket vs_client;

#define MSG_SEND_NUM_PRI_H	5
#define MSG_SEND_NUM_PRI_M	3
#define MSG_SEND_NUM_PRI_L	1

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

int vs_tls_buff_init()
{
	vs_client.rcv_buffer = malloc(VS_SK_RCV_MAX_LEN);
	if (NULL == vs_client.rcv_buffer)
		return VS_ERR;
	vs_client.rcv_buffer_size = VS_SK_RCV_MAX_LEN;

	return VS_OK;
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
                                4096, 1, 1,
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

int vs_mbedtls_connect()
{
	int ret = 0;
	char port[16] = {0};
	struct vs_ep_cfg *cfg = vs_ep_cfg_get();

	mbedtls_net_free(&(vs_client->ctx.net_ctx));
	mbedtls_ssl_session_reset(&(vs_client->ctx.ssl_ctx));
	snprintf(port, sizeof(port), "%d", cfg->remote_port);

	if(mbedtls_net_connect(&(vs_client->ctx.net_ctx),
							(const char *)(cfg->remote_ip),
							(const char *)port, MBEDTLS_NET_PROTO_TCP))
		return VS_ERR;

	mbedtls_ssl_set_bio(&(vs_client->ctx.ssl_ctx),
					&(vs_client->ctx.net_ctx),
					mbedtls_net_send,
					mbedtls_net_recv,
					mbedtls_net_recv_timeout);

    mbedtls_net_set_block(&(vs_client->ctx.net_ctx));
	ret = mbedtls_ssl_handshake(&(vs_client->ctx.ssl_ctx));
	if (ret != MBEDTLS_ERR_SSL_WANT_READ
		&& ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		return VS_ERR;


	return VS_OK;	
}

void* vs_mbedtls_rcv(void *arg)
{
	int ret = 0;
	char ret_dp = 0;
	short *len = NULL;
	struct rule_rcv_result result;
	struct vs_msg_head *msg_head = NULL;
	struct vs_msg_body_prefix *body_prefix = NULL;

	while (1) {
		usleep(20000);
	    
        if (vs_client.ctx.net_ctx.fd <= 0)
            continue;
	
		ret = mbedtls_ssl_read(&(vs_client->ctx.ssl_ctx),
						vs_client.rcv_buffer,
						vs_client.rcv_buffer_size);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ
            || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret < 0) {
            pthread_mutex_lock(&(vs_client.mutex));
            mbedtls_net_free(&(vs_client.ctx.net_ctx));	
            pthread_mutex_unlock(&(vs_client.mutex));	
        }

		msg_head = (struct vs_msg_head *)(vs_client.rcv_buffer);
		body_prefix = (struct vs_msg_body_prefix *)(vs_client.rcv_buffer + sizeof(struct vs_msg_head));	
		
		ret_dp = rcv_process(vs_client.rcv_buffer, ret);

		memset(&result, 0, sizeof(result));
		result.tag = body_prefix->tag;
		len = (short *)(result.len);
		*len = 1;
		*len = htons(*len);
		result.result = ret_dp;
		if (0 = msg_head->subpkg)
			send_process(msg_head->cmd, (char *)(&result), sizeof(result), VS_QUEUE_PRI_H, 0);	
	}
}

void vs_mbedtls_send_do(char pri)
{
	int ret = 0;
	char *data = NULL;
	queue_t *q = NULL;
	short data_len = 0;
	
	q = vs_queue_get(pri);
 	if (NULL == q)
		return;

	data = (char *)queue_pop_left(q);
	if (NULL == data)
		return;
	
	data_len = *((short *)data);

	//to do list
	//1. local storage 
	//2. send fail, reconect ssl?
	//3. compress
	ret = mbedtls_ssl_write(&(vs_client->ctx.ssl_ctx), (const unsigned char *)(data+sizeof(short)), data_len);

	//to do current-limiting 4G
	if (ret > 0)
		send_data_len_total += data_len;

	if (data) {
		memset(data, 0, (data_len + sizeof(short)));
		free(data);
		data = NULL;
	}
}

void* vs_mbedtls_send(void *arg)
{
    unsigned char i = 0;
    unsigned char j = 0;
    unsigned char num = 0;

	while (1) {
		usleep(50000);
    	
		for (i = 0; i < VS_QUEUE_PRI_END; i++) {
			
			if (i == VS_QUEUE_PRI_H)
				num = MSG_SEND_NUM_PRI_H;
			else if (i == VS_QUEUE_PRI_M)
				num = MSG_SEND_NUM_PRI_M;
			else if (i == VS_QUEUE_PRI_L)
				num = MSG_SEND_NUM_PRI_L;
			else 
				continue;

			for (j = 0; j < num; j++)
				vs_mbedtls_send_do(i);	
		}
	}
}

void* vs_mbedtls_create_task_run(void *arg)
{
	while (1) {
		sleep(3);

        pthread_mutex_lock(&(vs_client.mutex));	
        if (vs_client.ctx.net_ctx.fd <= 0)
            vs_mbedtls_connect();
        pthread_mutex_unlock(&(vs_client.mutex));	
	}
}

int vs_mbedtls_create_task()
{
	int ret = 0;
	pthread_t pid1;
	pthread_t pid2;
	pthread_t pid3;

    //connect or reconnet ssl
	ret = pthread_create(&pid1, NULL, &vs_mbedtls_create_task_run, NULL);
	if (ret)
		return VS_ERR;

	ret = pthread_create(&pid2, NULL, &vs_mbedtls_rcv, NULL);
	if (ret)
		return VS_ERR;

	ret = pthread_create(&pid3, NULL, &vs_mbedtls_send, NULL);
	if (ret)
		return VS_ERR;

	return VS_OK;
}

void vs_socket_init()
{
   pthread_mutex_init(&(vs_client.mutex), NULL); 
}

int communication_init()
{
	struct vs_ep_cfg *cfg = vs_ep_cfg_get();

	if (NULL == cfg)
		return VS_ERR;

    vs_socket_init();

	if (VS_OK != vs_tls_buff_init())
		return VS_ERR;
	
	if (VS_OK != vs_mbedtls_init())
		return VS_ERR;

	if (VS_OK != vs_mbedtls_create_task())
		return VS_ERR;

	return VS_OK;	
}
