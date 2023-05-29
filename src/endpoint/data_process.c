#include "comm.h"
#include "data_process.h"

static process_func rcv_data_func[VS_CMD_LEN][VS_TAG_LEN] = {0}; 

char rcv_data_process(uint8_t *data, int data_len)
{
	process_func func;

	if (NULL == data
		|| data_len <= 0
		|| data_len > VS_SK_RCV_MAX_LEN)
		return VS_ERR;

	
		
}

//response rule rcv
char response_data_process(uint8_t cmd, uint8_t tag, char result)
{

}
