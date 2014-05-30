/*-
 * Copyright (c) 2007-2009, Thomas Hurst <tom@hur.st>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <pthread.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "thrqueue.h"

#ifdef NDEBUG
# define AZ(foo)  do { if ((foo) != 0) abort(); } while (0)
#else
# define AZ(foo)      do { assert((foo) == 0); } while (0)
#endif

struct Queue *
queue_init ()
{
	struct Queue *q;
	q = (struct Queue *)malloc(sizeof(struct Queue));

	if (q)
	{
		q->length = 0;
		q->limit = -1;
		q->pool_length = 0;
		q->pool_limit = -1;
		q->enq_waiters = 0;
		AZ(pthread_mutex_init(&q->mutex, NULL));
		AZ(pthread_cond_init(&q->cv, NULL));
		AZ(pthread_cond_init(&q->enq_wait_cv, NULL));
		STAILQ_INIT(&q->queue);
		STAILQ_INIT(&q->pool);
	}
	return(q);
}

int 
queue_destroy (q)
struct Queue *q;
{
	struct QueueEntry *qi;
	if (!q)
		return 0;

	assert(STAILQ_EMPTY(&q->queue));
	while (!STAILQ_EMPTY(&q->pool))
	{
		qi = STAILQ_FIRST(&q->pool);
		STAILQ_REMOVE_HEAD(&q->pool, entries);
		q->pool_length--;
		free(qi);
	}
	AZ(pthread_cond_destroy(&q->cv));
	AZ(pthread_cond_destroy(&q->enq_wait_cv));
	AZ(pthread_mutex_destroy(&q->mutex));
	free(q);
	return 1;
}

int 
queue_empty (q)
struct Queue *q;
{
	/* This is safe as it's just checking if the head pointer == NULL */
	return(STAILQ_EMPTY(&q->queue));
}

int 
queue_full (q)
struct Queue *q;
{
	return (q->limit > 0 && q->length >= q->limit);
}

int 
queue_enq (q, item)
struct Queue *q;
void *item;
{
	struct QueueEntry *qi;
	if (!q)
		return 0;

	AZ(pthread_mutex_lock(&q->mutex));
	if (queue_full(q))
	{
		q->enq_waiters++;
		while (queue_full(q))
		{
			pthread_cond_wait(&q->enq_wait_cv, &q->mutex);
		}
		q->enq_waiters--;
	}

	if (!STAILQ_EMPTY(&q->pool))
	{
		qi = STAILQ_FIRST(&q->pool);
		STAILQ_REMOVE_HEAD(&q->pool, entries);
		q->pool_length--;
	}
	else
	{
		if (!(qi = (struct QueueEntry *)malloc(sizeof(struct QueueEntry))))
			abort(); // we never check if we succeed, so might as well abort()
	}

	qi->item = item;

	STAILQ_INSERT_TAIL(&q->queue, qi, entries);
	q->length++;
	AZ(pthread_cond_signal(&q->cv));
	AZ(pthread_mutex_unlock(&q->mutex));
	return 1;
}

void *
queue_deq (q)
struct Queue *q;
{
	void *ret = NULL;
	struct QueueEntry *qi;
	if (!q)
		return ret;

	AZ(pthread_mutex_lock(&q->mutex));
	while (STAILQ_EMPTY(&q->queue))
		AZ(pthread_cond_wait(&q->cv, &q->mutex));

	qi = STAILQ_FIRST(&q->queue);
	STAILQ_REMOVE_HEAD(&q->queue, entries);
	q->length--;
	ret = qi->item;
	if (q->pool_limit < 0 || q->pool_length < q->pool_limit)
	{
		STAILQ_INSERT_TAIL(&q->pool, qi, entries);
		q->pool_length++;
	}
	else free(qi);

	if (q->enq_waiters > 0)
		pthread_cond_signal(&q->enq_wait_cv);
	AZ(pthread_mutex_unlock(&q->mutex));
	return ret;
}

int 
queue_length (q)
struct Queue *q;
{
	return(q->length);
}

int 
queue_pool_length (q)
struct Queue *q;
{
	return(q->pool_length);
}

void 
queue_limit (q, limit)
struct Queue *q;
int limit;
{
	q->limit = limit;
}

void 
queue_pool_limit (q, limit)
struct Queue *q;
int limit;
{
	q->pool_limit = limit;
}

#ifdef BUILD_EXAMPLE
#include <unistd.h>

#define PRODUCER_ITERS 10000
#define CONSUMER_THREADS 4
#define PRODUCER_THREADS 2

struct Queue *q;

void *
consume(void *args)
{
	char *buf;
	int *bla = args;
	int id = *bla;

	printf("Consumer %d launched, waiting for producer...\n", id);
	while ((buf = queue_deq(q)))
	{
		printf("Consumer %d ate '%s'\n", id, buf);
		fflush(stdout);
		free(buf);
#ifndef NOSLEEP
		usleep(random() % 100000);
#endif
	}
	printf("Consumer %d got a NULL, queue consumed, bye!\n", id);
	return 0;
}

void *
produce (args)
void *args;
{
	int i;
	char *str;
	int *bla = args;
	int id = *bla;

	printf("Producer %d launched, stand by...\n", id);
	for(i=0;i<PRODUCER_ITERS;i++)
	{
		str = malloc(256);
		sprintf(str, "Iteration %d", i);
		printf("Producer %d making '%s'\n", id, str);
		fflush(stdout);
		queue_enq(q, str);
#ifndef NOSLEEP
		usleep(random() % 10000);
#endif
	}
	printf("Producer %d is done, bye!\n", id);
	return 0;
}


int 
main (argc, argv)
int argc;
char *argv[];
{
	pthread_t producers[PRODUCER_THREADS];
	pthread_t consumers[CONSUMER_THREADS];
	int i;
	int ids[PRODUCER_THREADS + CONSUMER_THREADS];

	srandomdev();

	printf("Init queue...\n");
	q = queue_init();
	queue_limit(q, 5);
	printf("Done, queue allocated at %p, starting workers\n", (void *)q);

	for (i=0; i < PRODUCER_THREADS; i++)
	{
		ids[i] = i;
		AZ(pthread_create(&producers[i], NULL, produce, &ids[i]));
	}

	for (i = 0; i < CONSUMER_THREADS; i++)
	{
		ids[i] = i;
		AZ(pthread_create(&consumers[i], NULL, consume, &ids[i]));
	}

	for (i=0;i < PRODUCER_THREADS;i++)
		if (producers[i])
			pthread_join(producers[i], NULL);

	for (i=0;i < CONSUMER_THREADS;i++)
		if (consumers[i])
			queue_enq(q, NULL);

	for (i=0;i < CONSUMER_THREADS;i++)
		if (consumers[i])
			pthread_join(consumers[i], NULL);

	printf("Ok, still alive.  Now see if destroy works...\n");
	queue_destroy(q);
	printf("Still here.  Time to go.\n");
	return 0;
}

#endif

