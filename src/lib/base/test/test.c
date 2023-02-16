#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <pthread.h>
#include "queue.h"


queue_t *q = NULL;

char *random_str()
{
	int i = 0;
	int size = 10;
	char *str = NULL;
	
	str = malloc(size);
	if (NULL == str)
		printf("random_str fail\n");
	memset(str, 0, size);

	for (i = 0; i < (size-1); i++)
		str[i] = 'A' + rand() % 26;

	return str;
}

static void *enqueue_work(void *arg)
{
	int num = 20;
	char *str = NULL;

	while (1) {
		if (0 == num)
			break;
		usleep(1000*300);
		str = random_str();
		if (str) {
			queue_push_right(q, str);
			printf("enqueue_work: [%s]\n", str);
		}
		num--;
	}

}

static void *dequeue_work(void *arg)
{
	char *str = NULL;

	while (1) {
		usleep(1000*300);
		str = queue_pop_left(q);
		if (str)
			printf("dequeue_work: [%s]\n", str);
		else {
			printf("dequeue_work: [NULL]\n");
			sleep(1);
		}
	}
}

int main (int argc, char *argv[])
{
	pthread_t threads1;
	pthread_t threads2;
	pthread_t threads3;
	pthread_t threads4;

	q = queue_create();
	if (NULL == q)
		printf("queue create fail\n");

	pthread_create(&threads1, NULL, enqueue_work, NULL);
	pthread_create(&threads2, NULL, enqueue_work, NULL);
	pthread_create(&threads3, NULL, dequeue_work, NULL);
	pthread_create(&threads4, NULL, dequeue_work, NULL);

	while (1) {
		sleep(100);
	}

	return 0;
}
