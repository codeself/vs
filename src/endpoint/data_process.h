#ifndef _DATA_PROCESS_H_
#define _DATA_PROCESS_H_

#define VS_CMD_LEN		1
#define VS_TAG_LEN		1	
#define VS_VALUE_LEN	2
#define VS_TM_LEN		8

struct vs_msg_head {
	uint8_t version;
	uint8_t cmd;
	uint8_t timestamp[VS_TM_LEN];
	uint8_t subpkg;
};

struct vs_msg_body_prefix {
	uint8_t tag;
	uint8_t len[VS_VALUE_LEN];
};

typedef char (*process_func)(uint8_t *data, int data_len);

char rcv_process(uint8_t *data, int data_len);
char send_process(uint8_t cmd, char *data, uint16_t data_len, uint8_t pri, uint8_t subpkg);

char rcv_func_register(uint8_t cmd, uint8_t tag, process_func *func);
#endif
