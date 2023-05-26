#ifndef _COMM_H_
#define _COMM_H_

typedef uint8_t  unsigned char
typedef uint16_t unsigned short
typedef uint32_t unsigned int
typedef uint64_t unsigned long long

#define VS_OK	0
#define VS_ERR	1

#define VS_IP_MAX_LEN					40
#define VS_PORT_MAX_LEN					6
#define VS_PATH_MAX_LEN					256
#define VS_FILE_NAME_MAX_LEN    		64
#define VS_CPT_MAX_LEN					64
#define VS_SK_RCV_MAX_LEN				65536
#define VS_ED_CFG   					"/data/vs-ep-cfg"
#define VS_EP_CFG_FILE_MAX_SIZE     	(512*1024)
#define VS_EP_LOG_FILE_MAX_SIZE     	(2*1024*1024)

#endif
