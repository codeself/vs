#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "comm.h"
#include "cfg_parse.h"

int communication_init()
{
	struct vs_ep_cfg *cfg = vs_ep_cfg_get();

	if (NULL == cfg)
		return VS_ERR;

	

	return VS_OK;	
}
