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

static mbedtls_x509_crt_profile x509_crt_profile =
{
	MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA1 ) |
	MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA224 ) |
	MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 ) |
	MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA384 ) |
	MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA512 ),
	0xFFFFFFF, /* Any PK alg    */
	0xFFFFFFF, /* Any curve     */
	2048,      /* 密钥长度为2048 */
};

static int mbedtls_ssl_sig_hashes[] =
{
	MBEDTLS_MD_SHA512,
	MBEDTLS_MD_SHA384,
	MBEDTLS_MD_SHA256,
	MBEDTLS_MD_SHA224,
	MBEDTLS_MD_SHA1,
	MBEDTLS_MD_NONE
};

struct rule_rcv_result {
	uint8_t tag;
	uint8_t len[2];
	char result;
};

#endif
