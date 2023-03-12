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
    char log_format[1024] = {0};

    pthread_mutex_lock(&log_mtx);
    gettimeofday(&tv, &tz);
    t = localtime(&tv.tv_sec);
    if (NULL == t || NULL == log) {
        pthread_mutex_unlock(&log_mtx);
        return;
    }
    
    snprintf(log_format, sizeof(log_format), "[%d-%d-%d %d:%d:%d.%ld] %s",
                1900+t->tm_year, 1+t->tm_mon, t->tm_mday,
                t->tm_hour, t->tm_min, t->tm_sec, tv.tv_usec, log);

    log_format[sizeof(log_format) - 1] = 0;

    fwrite(log_format, 1, strlen(log_format), log_fp);

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
