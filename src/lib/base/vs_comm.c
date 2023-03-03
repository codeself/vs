#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vs_base.h"
#include "vs_queue.h"

queue_t *vs_comm_msg_queue_h = NULL;
queue_t *vs_comm_msg_queue_m = NULL;
queue_t *vs_comm_msg_queue_l = NULL;
struct vs_comm_manager *vs_event_sock_xtgb0z1r_t8u9z212f = NULL;

uint8_t vs_comm_msg_queue_init()
{
	vs_comm_msg_queue_h = queue_create();
	if (NULL == vs_comm_msg_queue_h)
		return VS_BASE_ERR;

	vs_comm_msg_queue_m = queue_create();
	if (NULL == vs_comm_msg_queue_m) {
		queue_destroy(vs_comm_msg_queue_h);
		vs_comm_msg_queue_h = NULL;
		return VS_BASE_ERR;
	}

	vs_comm_msg_queue_l = queue_create();
	if (NULL == vs_comm_msg_queue_l) {
		queue_destroy(vs_comm_msg_queue_m);
		vs_comm_msg_queue_m = NULL;

		queue_destroy(vs_comm_msg_queue_h);
		vs_comm_msg_queue_h = NULL;
	}

	return VS_BASE_OK;
}

static queue_t *vs_msg_get_queue_by_cmd_id(uint8_t cmd, uint8_t msg_id)
{
	return vs_comm_msg_queue_h; 
}

uint8_t vs_msg_enqueue(queue_t *q, void *msg)
{
	if (NULL == q || NULL == msg)
		return VS_BASE_ERR;
	
	if (queue_push_right(q, msg))
		return VS_BASE_ERR;

	return VS_BASE_OK;
}

uint8_t vs_msg_enqueue_by_cmd_id(uint8_t cmd, uint8_t msg_id, void *msg, uint16_t msg_len)
{
	void *msg_cache = NULL;

	if (NULL == msg
		|| 0 == msg_len
		|| msg_len > VS_MSG_DATA_MAX_LEN)
		return VS_BASE_ERR;

	msg_cache = malloc(msg_len);
	if (NULL == msg_cache)
		return VS_BASE_ERR;

	memcpy(msg_cache, msg, msg_len);
	
	return vs_msg_enqueue(vs_msg_get_queue_by_cmd_id(cmd, msg_id), msg_cache);
}

void vs_set_event_send_sock(struct vs_comm_manager *sock)
{
	vs_event_sock_xtgb0z1r_t8u9z212f = sock;
}

//data format: |cmd|event_id|L|V
uint8_t vs_event_report(uint8_t cmd, uint8_t event_id, void *data, uint16_t data_len)
{
	ssize_t ret = 0;

	if (NULL == data)
		return VS_BASE_ERR;
	
	if (NULL == vs_event_sock_xtgb0z1r_t8u9z212f)
		return VS_BASE_ERR;

	pthread_mutex_lock(&(vs_event_sock_xtgb0z1r_t8u9z212f->mutex));
	if ((vs_event_sock_xtgb0z1r_t8u9z212f->fd < 0)
		&& (NULL == vs_event_sock_xtgb0z1r_t8u9z212f->offline_log.fd)) {
		pthread_mutex_unlock(&(vs_event_sock_xtgb0z1r_t8u9z212f->mutex));
		return VS_BASE_ERR;
	}	
	
	ret = send(vs_event_sock_xtgb0z1r_t8u9z212f->fd, data, data_len, 0);
	if (ret != data_len) {
		if (vs_event_sock_xtgb0z1r_t8u9z212f->offline_log.fd) {
			fwrite(data, data_len, 1, vs_event_sock_xtgb0z1r_t8u9z212f->offline_log.fd);	
		}
	}
		
	pthread_mutex_unlock(&(vs_event_sock_xtgb0z1r_t8u9z212f->mutex));	

	return VS_BASE_OK;	
}
