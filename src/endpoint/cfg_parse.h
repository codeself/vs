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
#define PKI_PATH_KEY			"pki_file_path"
#define CA_FILE1_KEY			"ca_file1_name"
#define PKEY_FILE1_KEY			"pkey_file1_name"
#define CA_FILE2_KEY			"ca_file2_name"
#define PKEY_FILE2_KEY			"pkey_file2_name"
#define COMPONENT_KEY			"components"

struct vs_ep_cfg {
	uint8_t remote_ip[VS_IP_MAX_LEN];
	long remote_port;
	long heartbeat_max_times;
	long heartbeat_interval;

	long mem_max;
	long cpu_max;

	long run_log_max;
	long offline_eve_log_max;
	long offline_eve_log_expire;
};

int vs_cfg_parse(char *file);
struct vs_ep_cfg* vs_ep_cfg_get();

#endif
