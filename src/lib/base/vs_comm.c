#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vs_base.h"
#include "vs_queue.h"

queue_t *vs_comm_msg_queue_h = NULL;
queue_t *vs_comm_msg_queue_m = NULL;
queue_t *vs_comm_msg_queue_l = NULL;
struct vs_comm_sock *vs_comm_msg_send_sock = NULL;

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
