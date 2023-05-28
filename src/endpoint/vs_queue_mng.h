#ifndef _VS_QUEUE_MNG_H_
#define _VS_QUEUE_MNG_H_
#include "queue.h"

enum queue_level {
    VS_QUEUE_PRI_H,
    VS_QUEUE_PRI_M,
    VS_QUEUE_PRI_L,
    VS_QUEUE_PRI_END
};

int vs_queue_init();
queue_t* vs_queue_get(unsigned char index);

#endif
