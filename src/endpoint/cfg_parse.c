#include "comm.h"
#include "cfg_parse.h"

//max 512kb
#define VS_EP_CFG_FILE_MAX_SIZE		(512*1024)
static struct vs_ep_cfg cfg;

int vs_cfg_parse_json(char *text, size_t size)
{
	int ret = VS_ERR;
	json_t *json = NULL;
	json_t *json_item = NULL;
	json_error_t error;
	char *js_string_value = NULL;
	long js_int_value = 0;

	if (NULL == text
		|| size <= 0 || size > VS_EP_CFG_FILE_MAX_SIZE)
		return VS_ERR;

	memset(&error, 0, sizeof(json_error_t));
	json = json_loadb(text, size, 0, &error);
	if (NULL == json)
		return VS_ERR;

	json_item = json_object_get(json, REMOTE_IP_KEY);
	if (json_item) {
		if (json_is_string(json_item)) {
			js_string_value = json_string_value(json_item);
			if (strlen(js_string_value) >= VS_IP_MAX_LEN)
				goto out;

			snprintf(cfg.remote_ip, VS_IP_MAX_LEN, "%s", js_string_value);
		} else {
			goto out;
		}
	}

	json_item = json_object_get(json, REMOTE_PORT_KEY);
	if (json_item) {
		if (json_is_integer(json_item)) {
			cfg.remote_port = json_integer_value(json_item);
			if (cfg.remote_port < 0 || cfg.remote_port > 65535)
				goto out;
		} else {
			goto out;
		}
	}

	json_item = json_object_get(json, HB_MAX_TIMES_KEY);
	if (json_item) {
		if (json_is_integer(json_item)) {
			cfg.heartbeat_max_times = json_integer_value(json_item);
			if (cfg.heartbeat_max_times < 10)
				goto out;
		} else {
			goto out;
		}
	}

	json_item = json_object_get(json, HB_INTERVA_KEY);
	if (json_item) {
		if (json_is_integer(json_item)) {
			cfg.heartbeat_interval = json_integer_value(json_item);
			if (cfg.heartbeat_interval < 10)
				goto out;
		} else {
			goto out;
		}
	}

	json_item = json_object_get(json, MEM_MAX_KEY);
	if (json_item) {
		if (json_is_integer(json_item)) {
			cfg.mem_max = json_integer_value(json_item);
			if (cfg.mem_max < 20 || cfg.mem_max > 100)
				goto out;
		} else {
			goto out;
		}
	}

	json_item = json_object_get(json, CPU_MAX_KEY);
	if (json_item) {
		if (json_is_integer(json_item)) {
			cfg.cpu_max = json_integer_value(json_item);
			if (cfg.cpu_max < 1 || cfg.cpu_max > 20)
				goto out;
		} else {
			goto out;
		}
	}

	ret = VS_OK;

out:
	json_decref(json);

	return ret;
}

int vs_cfg_parse(char *file)
{
	int ret = VS_ERR;
	size_t len = 0;
	FILE *fp = NULL;
	char *buff = NULL;
	char *plaintext = NULL;
	int cfg_file_size = 0;
	void *cfg_data = NULL;
	uint8_t iv_or_nonce[16] = {0xa1, 0x02, 0x34, 0x93, 0x2f, 0x8e, 0x02, 0x18,
							   0x6f, 0xf1, 0x4d, 0x7c, 0xfb, 0xaa, 0xf2, 0xfe};

	
	if (NULL == file)
		return VS_ERR;

	cfg_file_size = vs_get_file_size(file);
	if (cfg_file_size <= 0
		|| cfg_file_size > VS_EP_CFG_FILE_MAX_SIZE)
		return VS_ERR;

	fp = fopen(file, "r");
	if (NULL == fp)
		return VS_ERR;	
	
	buff = malloc(cfg_file_size);
	if (NULL == buff) {
		ret = VS_ERR;
		goto out1;
	}
		
	len = fread((void *)buff, 1, cfg_file_size, fp);	
	if (len != cfg_file_size) {
		ret = VS_ERR;
		goto out2;
	}

	plaintext = malloc(cfg_file_size);
	if (NULL == plaintext) {
		ret = VS_ERR;
		goto out2;
	}
	
	aes_whitebox_decrypt_ctr(iv_or_nonce, buff, cfg_file_size, plaintext);
	ret = vs_cfg_parse_json(plaintext, cfg_file_size);

	free(plaintext);
	plaintext = NULL;

out2:
	free(buff);
	buff = NULL;
out1:
	fclose(fp);
	fp = NULL;

	return ret;
}

struct vs_ep_cfg* vs_ep_cfg_get()
{
	return &cfg;
}
