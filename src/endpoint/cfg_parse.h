#ifndef _CFG_PARSE_H_
#define _CFG_PARSE_H_

#include "comm.h"

#define LOCAL_IP_KEY			"local_ip"
#define LOCAL_PORT_KEY			"local_port"
#define REMOTE_IP_KEY			"remoute_ip"
#define REMOTE_PORT_KEY			"remoute_port"
#define HB_MAX_TIMES_KEY		"heartbeat_max_times"
#define HB_INTERVA_KEY			"heartbeat_interval"
#define MEM_MAX_KEY				"mem_max"
#define CPU_MAX_KEY				"cpu_max"
#define RUN_LOG_MAX_KEY			"run_log_max"
#define RUN_LOG_PATH_KEY		"run_log_path"
#define OFFLINE_LOG_MAX_KEY 	"offline_log_max"
#define OFFLINE_LOG_PATH_KEY	"offline_log_path"
#define OFFLINE_LOG_EXPIRE_KEY	"offline_log_expire"
#define PKI_PATH_KEY			"pki_file_path"
#define CA_CLIENT_KEY			"ca_client"
#define CERT_CLIENT_KEY			"cert_client"
#define PKEY_CLIENT_KEY			"pkey_client"

struct vs_ep_cfg {
	uint8_t remote_ip[VS_IP_MAX_LEN];
	long remote_port;
	long heartbeat_max_times;
	long heartbeat_interval;

	long mem_max;
	long cpu_max;

	long run_log_max;
	uint8_t run_log_path[VS_PATH_MAX_LEN];
	
	long offline_log_max;
	long offline_log_expire;
	uint8_t offline_log_path[VS_PATH_MAX_LEN];

	uint8_t pki_file_path[VS_PATH_MAX_LEN];
	uint8_t ca_client[VS_FILE_MAX_LEN];
	uint8_t cert_client[VS_FILE_MAX_LEN];
	uint8_t pkey_client[VS_FILE_MAX_LEN];
	
	uint8_t components[VS_CPT_MAX_LEN];
};

int vs_cfg_parse(char *file);
struct vs_ep_cfg* vs_ep_cfg_get();

#endif
