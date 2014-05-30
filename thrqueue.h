#ifndef __THRQUEUE_H
#define __THRQUEUE_H
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

#include <sys/queue.h>

STAILQ_HEAD(QueueHead,QueueEntry);

struct Queue {
	pthread_mutex_t mutex;
	pthread_cond_t cv;
	pthread_cond_t enq_wait_cv;
	int enq_waiters;
	int length;
	int limit;
	int pool_length;
	int pool_limit;
	struct QueueHead queue;
	struct QueueHead pool;
};

struct QueueEntry {
	void *item;
	STAILQ_ENTRY(QueueEntry) entries;
};

struct Queue*queue_init();
int queue_destroy();
int queue_empty();
int queue_full();
int queue_enq();
int queue_length();
int queue_pool_length();
void queue_limit();
void queue_pool_limit();
void *queue_deq();

#endif
