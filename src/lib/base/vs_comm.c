#include <stdio.h>
#include <stdlib.h>
#include <stdstring.h>

#include "vs_base.h"

static int vs_comm_obj_fd = -1;
extern unsigned char *server_addr = NULL;

uint8_t vs_comm_client_connect()
{
	if (NULL == server_addr)
		return VS_BASE_SERVER_NULL;
}

uint8_t vs_send_msg_data(uint8_t cmd, uint8_t msg_id, void *msg_data, uint16_t msg_data_len)
{
	if (NULL == msg_data
		|| 0 == msg_data_len
		|| msg_data_len > VS_MSG_DATA_MAX_LEN)
		return VS_BASE_ERR;

	if (vs_comm_obj_fd <= 0) {
		ret = vs_comm_client_connect();
		if (ret)
			return ret;
	}
}
