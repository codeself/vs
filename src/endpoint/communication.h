#ifndef _COMMUNICATION_H_
#define _COMMUNICATION_H_

struct vs_socket {
	int fd;
	SSL *ssl_fd;
	uint8_t *rcv_buffer;
	int rcv_buffer_size;
	int rcv_len;
	uint8_t *send_buffer;
	int send_buffer_size;
	int send_len;

	pthread_mutex_t mutex;
};

#endif
