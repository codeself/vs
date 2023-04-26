#ifndef _COMMUNICATION_H_
#define _COMMUNICATION_H_

struct vs_mbedtls_context
{
	mbedtls_net_context net_ctx;
	mbedtls_ssl_context ssl_ctx;
	mbedtls_ssl_config ssl_cfg;
	mbedtls_ctr_drbg_context drbg_ctx;
	mbedtls_entropy_context etpy_ctx;
	mbedtls_x509_crt x509_ca_crt;
	mbedtls_x509_crt x509_client_crt;
	mbedtls_pk_context pkey;
};

struct vs_socket {
	int fd;
	struct vs_mbedtls_context ctx;
	uint8_t *rcv_buffer;
	int rcv_buffer_size;
	int rcv_len;
	uint8_t *send_buffer;
	int send_buffer_size;
	int send_len;

	pthread_mutex_t mutex;
};

#endif
