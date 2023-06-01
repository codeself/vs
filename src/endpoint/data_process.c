#include "comm.h"
#include "data_process.h"

static process_func rcv_func[VS_CMD_MAX][VS_TAG_MAX] = {0}; 

char build_report_msg_head(struct vs_msg_head *head, uint8_t cmd, uint8_t subpkg)
{
	uint64_t utime = 0;
	uint64_t *putime;
	struct timeval time;

	if (NULL == head)
		return VS_ERR;

	head->version = 1;
	head->cmd = cmd;
	head->subpkg = subpkg;
	
	gettimeofday(&time, NULL);
	utime = time.tv_sec * 1000000 + time.tv_usec;
	utime = vs_htonll(utime);
	putime = (uint64_t *)(head->timestamp);
	*putime = utime;

	return VS_OK;
}

char send_process(uint8_t cmd, char *data, uint16_t data_len, uint8_t pri, uint8_t subpkg)
{
	queue_t *q = NULL;
	char *value = NULL;
	size_t value_len = 0;	
	struct vs_msg_head head;

	if (null == data || pri >= vs_queue_pri_end)
		return VS_ERR;

	memset(&head, 0, sizeof(head));
	build_report_msg_head(&head, cmd, subpkg);

	q = vs_queue_get(pri);
	if (NULL == q)
		return VS_ERR;
	
	value_len = sizeof(vs_msg_head) + data_len;
	//to do 
	//1.write local log file
	//2. use mem pool
	value = malloc(value_len);
	if (NULL == value)
		return VS_ERR;	

	memcpy((void *)value, (const void *)(&head), sizeof(struct vs_msg_head));
	memcpy((void *)(value + sizeof(struct vs_msg_head)), (const void *)data, data_len);

	//to do write local log file
	if (queue_push_right(q, (void*)value))
		return VS_ERR;

	return VS_OK;
}

char rcv_process(uint8_t *data, int data_len)
{
	process_func func;
	uint8_t *tlv = NULL;
	struct vs_msg_head *head = NULL;

	if (NULL == data
		|| data_len <= (sizeof(struct vs_msg_head))
		|| data_len > VS_SK_RCV_MAX_LEN)
		return VS_ERR;
	
	head = (struct vs_msg_head *)data;	
	tlv = data + sizeof(struct vs_msg_head);

	if (head->cmd >= VS_CMD_MAX
		|| *tlv >= VS_TAG_MAX)
		return VS_ERR;

	func = rcv_func[head->cmd][tag];
	if (NULL == func)
		return VS_ERR;

	return func(tlv, (data_len - sizeof(struct vs_msg_head)))
}
