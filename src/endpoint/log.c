#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>

#include "comm.h"
#include "cfg_parse.h"

FILE *log_fp = NULL;
uint32_t log_size = 0;
pthread_mutex_t log_mtx;

void vs_log_output(char *log)
{
    struct timeval tv;
    struct timezone tz;
    struct tm *t;
	size_t log_len = 0;
    char log_format[1024] = {0};
    struct vs_ep_cfg *cfg = vs_ep_cfg_get();

    pthread_mutex_lock(&log_mtx);
    gettimeofday(&tv, &tz);
    t = localtime(&tv.tv_sec);
    if (NULL == t || NULL == log || log_len > cfg->run_log_max) {
        pthread_mutex_unlock(&log_mtx);
        return;
    }
    
    snprintf(log_format, sizeof(log_format), "[%d-%d-%d %d:%d:%d.%ld] %s",
                1900+t->tm_year, 1+t->tm_mon, t->tm_mday,
                t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec, log);

    log_format[sizeof(log_format) - 1] = 0;

	log_len = strlen(log_format);

    fwrite(log_format, 1, log_len, log_fp);
    fwrite("\n", 1, strlen("\n"), log_fp);
	log_size += log_len;
    log_size += strlen("\n");	

    pthread_mutex_unlock(&log_mtx);
}

int log_init()
{
    char log_file[512] = {0};
    struct vs_ep_cfg *cfg = vs_ep_cfg_get();

    if (NULL == cfg)
        return VS_ERR;
    
    pthread_mutex_init(&log_mtx, NULL);    
    
    snprintf(log_file, sizeof(log_file), "%s/%s", cfg->run_log_path, "run_log");

    log_fp = fopen(log_file, "w");
    if (NULL == log_fp)
        return VS_ERR;    
    
    return VS_OK;
}
