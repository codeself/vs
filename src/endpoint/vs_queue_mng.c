#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "comm.h"

queue_t* queue_arr[VS_QUEUE_PRI_END];

int vs_queue_init()
{
    int i = 0;

    for (i = 0; i < VS_QUEUE_PRI_END; i++) {
        queue_arr[i] = queue_create();
        if (NULL == queue_arr[i])
            return VS_ERR;
    }

    return VS_OK;    
}

queue_t* vs_queue_get(unsigned char index)
{
    if (index >= VS_QUEUE_PRI_END)
        return NULL;

    return queue_arr[index];    
}
