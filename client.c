#include "includes.h"
#include "defines.h"

#include "msgiddbd.h"
#include "misc.h"

#include "logfile.h"
#include "client.h"
#include "logmsg.h"
#include "table.h"

#include "thrqueue.h"
#include "html.h"

#include "client.h"

extern struct ShareData *g; /* global shared data */

int32_t segment_sort(const void *a, const void *b)
{
	return (*(struct segment **)a)->segment
	     - (*(struct segment **)b)->segment;
}

int32_t client_do_send_fileid(fd_t fd, fileid_t fileid)
{
	uint16_t segments_sent_in_page, segments_sent_total;
	uint32_t mes, n, l, h, sl_used;
	int64_t r, bufused;
	char *e, *bp, buf[SOCK_BUFSIZE];
	struct fileid *f;
	struct dat_files *d;

	struct segments *ss;
	struct segment *s, *sl[SL_SIZE], *p;

	if (fileid > MAX_SANE_FILEID)
	{
		sockwrite(fd, RESPONSE_501, fileid);
		return -1;
	}

	if ((d = get_table_for_fileid(fileid, 0)) == NULL)
	{
		sockwrite(fd, RESPONSE_404, fileid);
		return -1;
	}

	f = &d->f.files[fileid - d->f.fh->fileid_min_req];
	if (f->fileid != fileid)
	{
		sockwrite(fd, RESPONSE_404, fileid);
		return -1;
	}

	/* we need a read lock on the table */
	if (table_lock(d, T_RDLOCK))
	{
		logmsg_f(LOG_ERR, "table_lock error");
		sockwrite(fd, RESPONSE_501, fileid);
		return -1;
	}

	sl_used = 0;
	segments_sent_total = 0;

#if USE_M_LOCK
	uint32_t *m_lock;
	m_lock = &d->f->m_lock[fileid - d->f->fh->fileid_min_req];

	/* if this m_lock is non-zero, something else is updating this
	 * segment.. wait for it */
	while (!atomic_cmpset_int(m_lock, 0, 1))
	{
		logmsg(LOG_DEBUG, "waiting.. (m_lock is %d)", *m_lock);
		sleep(1);
	}
#endif

	/* now we can start reading segments */
	ss = get_first_segments_for_file(d, f);

	/* copy into a local array for sorting */
	do
	{
		if (ss == &sentinels.segment_page_out_of_bounds)
		{
			abort();
		}

		if (ss->magic != SEGMENTS_MAGIC)
		{
			logmsg_f(LOG_CRIT, "ss->magic invalid at offset %p! "
			    "(fileid=%lu, magic=%x)",
			    calc_segments_offset(d, ss), f->fileid, ss->magic);

			table_unlock(d);
			sockwrite(fd, RESPONSE_501, fileid);
			return -1;
		}

		h = MurmurHash2((char *)ss + sizeof(struct segments),
		    ss->size_used, MURMURHASH_SEED);
		if (ss->hash != h)
		{
			logmsg_f(LOG_ERR, "ss->hash mismatch (got %x, want %x) "
			    "at %s:%p", ss->hash, h, d->basename, ss);
			table_unlock(d);
			sockwrite(fd, RESPONSE_501, fileid);
			return -1;
		}

		segments_sent_in_page = 0;
		s = ss->segments;
		while(segments_sent_in_page < ss->segment_count)
		{
			segments_sent_in_page++;
			segments_sent_total++;

			sl[sl_used++] = s;

			if (sl_used == SL_SIZE)
			{
				/* out of room in sl :( */
				logmsg_f(LOG_CRIT, "sl full on fileid=%lu", fileid);
				sockwrite(fd, RESPONSE_501, fileid);
				table_unlock(d);
				return -1;
			}

			/* point at next segment */
			s = (struct segment *)((char *)s
			    + sizeof(struct segment) + s->msgid_len);
		}

	} while ((ss = get_next_segments(d->s.m, ss)));

#if USE_M_LOCK
	/* unlock the m_lock, everything from now on is locally stored */
	atomic_subtract_int(m_lock, 1);
#endif

	/* sort sl by segment member */
	qsort(sl, sl_used, sizeof(struct segment *), segment_sort);

	sockwrite(fd, "205 FILEID %lu", fileid);

	/* send them all; cut down on write() calls by caching in buf */
	bufused = 0;
	bp = buf;
	e = html_entities_ascii_buffer(256);
	mes = html_entities_max_entity_size() * 256;
	for(n = 0 ; n < sl_used ; n++)
	{
		p = sl[n];

		l = html_entities_ascii(p->msgid, p->msgid_len, e);
		r = sprintf(bp,
		  "\t\t\t<segment bytes=\"%d\" number=\"%d\">%.*s</segment>\n",
		  p->size, p->segment, l, e);

		bufused += r;
		bp += r;

		if (bufused + mes + 20 > SOCK_BUFSIZE)
		{
			if (-1 == write(fd, buf, bufused))
			{
				table_unlock(d);
				free(e);
				return -1;
			}

			bufused = 0;
			bp = buf;
		}

		atomic_inc_64(g->segments_selected);
	}

	/* release table lock */
	table_unlock(d);

	free(e);

	if (bufused && -1 == write(fd, buf, bufused))
		return -1;

	if (-1 == sockwrite(fd, "."))
		return -1;

	return 0;

}
void client_do_get(struct client *self, char *sbuf)
{
	/* expected format:
	 * get fileid1 [fileid2] [fileid3] [..]
	*/

	fd_t fd = self->client_fd;
	char *p = sbuf;
	char *c;
	fileid_t fileid;

	for(p = strtok_r(p, " ", &c) ; p ; p = strtok_r(NULL, " ", &c))
	{
		fileid = atol(p);
		client_do_send_fileid(fd, fileid);
	}

}

void client_do_commit(struct client *self, char *sbuf)
{
	(void)self; (void)sbuf;
	int32_t r;
	fd_t fd = self->client_fd;

	if (!self->logbuf || self->logbuf->used == 0)
	{
		sockwrite(fd, RESPONSE_300);
		return;
	}

	r = logfile_commit(g->l, self->logbuf, LOG_COMMIT_GET_LOCK);

	if (r == -1)
	{
		/* some sort of failure */
		sockwrite(fd, RESPONSE_504);
		return;
	}

	sockwrite(fd, RESPONSE_200);
}

int split_put(char *in, struct segment_local *sl)
{
	char *p = in, *p2;

	p2 = strchr(p, ':');
	if (! p2)
		return -1;

	/* fileid */
	sl->fileid = atol(p);

	p = p2 + 1;
	p2 = strchr(p, ':');
	if (! p2)
		return -1;

	/* segment */
	sl->segment = atol(p);

	p = p2 + 1;
	p2 = strchr(p, ':');
	if (! p2)
		return -1;

	/* date */
	sl->date = atol(p);

	p = p2 + 1;
	p2 = strchr(p, ':');
	if (! p2)
		return -1;

	/* size */
	sl->size = atol(p);

	p = p2 + 1;

	/* msgid */
	strcpy(sl->msgid, p);
	sl->msgid_len = strlen(sl->msgid);

	return 0;
}

void client_do_put(struct client *self, char *sbuf, int32_t flags)
{
	/* expected format:
	 * put fileid:segment:date:size:msgid
	 *
	 * segment is sanity checked to be 1-65535
	 * date is sanity checked to be 1y < now < 1y
	 * size is sanity checked to be 0 - 15MB
	*/
	fd_t fd = self->client_fd;
	struct statfs stats;
	struct logfile_entry e;
	time_t now = time(NULL);

	int32_t checkdupe = flags & PUT_CHECKDUPE;

	if (g->inserts_enabled == 0 || now - g->last_stat_time > 10)
	{
		if (statfs(g->cfg.dbroot, &stats) == -1)
		{
			logmsg_f(LOG_ERR, "statfs: %s", STR_errno);
			sockwrite(fd, "504 internal system error");
			g->inserts_enabled = 0;
			return;
		}
		g->inserts_enabled = (100.0 * stats.f_bfree/stats.f_blocks > 5);
		g->last_stat_time = now;
	}

	if (g->inserts_enabled == 0)
	{
		logmsg_f(LOG_CRIT, "refusing to insert segment, check diskspace");
		sockwrite(fd, RESPONSE_505);
		return;
	}

	/* split up the incoming line into e.d */
	if (split_put(sbuf, &e.d))
	{
		sockwrite(fd, RESPONSE_502);
		return;
	}

	/* some sanity checking */
	if (e.d.segment < 1 || e.d.segment > 65534)
	{
		sockwrite(fd, "503 segment (%d) out of bounds", e.d.segment);
		return;
	}

	if (e.d.date < now - ONE_YEAR || e.d.date > now + ONE_YEAR)
	{
		//sockwrite(fd, "503 date (%d) out of bounds", e.d.date);
		//return;
		logmsg_f(LOG_NOTICE,
		    "fileid=%lu segment=%lu: fixing out of bounds date %d",
		    e.d.fileid, e.d.segment, e.d.date);
		e.d.date = now;
	}

	if (e.d.size < 1 || e.d.size > 15 * 1024 * 1024)
	{
		sockwrite(fd, "503 size (%d) out of bounds", e.d.size);
		return;
	}

	/* if we've been asked to, ensure this msgid is not already present
	 * this isn't perfect, it could be in an uncommitted logfile, but
	 * it'll do (it's mostly for MySQL backfilling) */
	if (checkdupe && find_segment(&e.d))
	{
		sockwrite(fd, RESPONSE_310);
		return;
	}

	/* see if we need to open a logfile */
	if (g->l->fd == 0)
	{
		/* yes we do */
		if (logfile_create(g->l))
		{
			/* but it failed */
			sockwrite(fd, RESPONSE_504);
			return;
		}
	}

	/* check if we need to allocate self->logbuf */
	if (! self->logbuf)
		self->logbuf = logfile_buffer_alloc(LOGFILE_BUFFER_SIZE);

	/* add the segment */
	if (logfile_write_row(g->l, self->logbuf, &e))
	{
		/* error */
		sockwrite(fd, RESPONSE_504);
		return;
	}

	atomic_inc_64(g->segments_inserted);

	sockwrite(fd, RESPONSE_200);
}

void client_do_stats(struct client *self, const char *sbuf)
{
	(void)sbuf;
	int32_t i;
	struct master *m;
	struct slave *s;
	fd_t fd = self->client_fd;
	
	sockwrite(fd, RESPONSE_201);

	sockwrite(fd, "UPTIME: %lu sec",
	    (get_time_usec() -  g->time_start) / 1000000);

	sockwrite(fd, "TABLES/OPEN: %u", g->t->open_tables);
	sockwrite(fd, "TABLES/MAX: %u", g->t->dats_allocated);

	sockwrite(fd, "CLIENTS/OPEN: %u", g->open_clients);
	sockwrite(fd, "CLIENTS/TOTAL: %u", g->total_clients);
	sockwrite(fd, "CLIENTS/HANDLERS: %d", g->client_handler_count);

	sockwrite(fd, "SEGMENTS/INSERTED: %lu", g->segments_inserted);
	sockwrite(fd, "SEGMENTS/SELECTED: %lu", g->segments_selected);
	sockwrite(fd, "SEGMENTS/REPLICATED: %lu", g->segments_replicated);

	sockwrite(fd, "LOGFILE/NAME: %s",
	    g->l && g->l->fd ? logfile_get_current_name(g->l) : "(none)");
	sockwrite(fd, "LOGFILE/POS: %lu",
	    g->l && g->l->fd ? logfile_get_current_byte(g->l) : 0);


	/* display status of connected masters */
	for (i = 0 ; i < MAX_MSGIDDBDS_CONNECTED ; i++)
	{
		m = &g->masters[i];
		if (m->fd == 0) continue;

		sockwrite(fd, "MASTER: S:%d ID:%s LOG:%s POS:%lu ROWS:%lu",
		    i, m->id, m->log_file, m->log_pos, m->segments_replicated);
	}

	/* display status of connected slaves */
	for (i = 0 ; i < MAX_MSGIDDBDS_CONNECTED ; i++)
	{
		s = &g->slaves[i];
		if (s->fd == 0) continue;
		sockwrite(fd, "SLAVE: S:%d ID:%s LOG:%s POS:%lu",
		    i, s->id, s->log_file, s->log_pos);
	}

	sockwrite(fd, ".");
}

int32_t client_slave_send_rows_from_buf(struct slave *slv, struct logfile_entry *e, log_count_t c, ssize_t stop_at)
{
	char *p, buf[SOCK_BUFSIZE];
	uint32_t sent, len;
	ssize_t r;
	struct logfile_entry *ep;

	off_t local_log_pos = slv->log_pos;

	/* send rows from e in SOCK_BUFSIZE chunks until they're all gone or
	 * we're interrupted by slv->stop_replicating, in which case return
	 * gracefully */

	//logmsg(LOG_DEBUG, "have %d rows to send", c);
	//logmsg(LOG_DEBUG, "stop_at is %d", stop_at);

	ep = e;
	len = 0;
	sent = 0;
	while (sent < c)
	{
		if (slv->stop_replicating)
		{
			/* slave has sent 'STOP' */
			break;
		}

		p = buf + len;
		len += sprintf(p, "%s:%lu "
#if SLAVE_ROW_FORMAT_PRETTY
		    "ID=%u SEG=%u DATE=%u SIZE=%u MSGID=%s\n",
#else /* same format as a PUT */
		    "%u:%u:%u:%u:%s\n",
#endif
		    slv->log_file, local_log_pos,
		    ep->d.fileid, ep->d.segment, ep->d.date, ep->d.size,
		    ep->d.msgid);
		ep++; /* next pointer in logfile_entry array */

		local_log_pos += sizeof(struct logfile_entry);
		sent++;

		/* when we get near our limit, send it off */
		if (p - buf > SOCK_BUFSIZE - 512)
		{
			r = send(slv->fd, buf, len, 0);
			if (r == -1)
			{
				logmsg_f(LOG_ERR, "send: %s", STR_errno);
				return -1;
			}

			slv->log_pos = local_log_pos;

			p = buf; len = 0;
		}

		/* stop_at of zero means do the entire log */
		if (stop_at && local_log_pos == stop_at)
		{
			logmsg_f(LOG_DEBUG, "reached stop_at");
			break;
		}

	}

	/* if there are any rows remaining, send.. */
	if (len)
	{
		r = send(slv->fd, buf, len, 0);
		if (r == -1)
		{
			logmsg_f(LOG_ERR, "send: %s", STR_errno);
			return -1;
		}

		slv->log_pos = local_log_pos;
	}

	//logmsg(LOG_DEBUG, "sent %d rows", sent);

	return 0;
}

int32_t client_slave_read_and_send_rows(struct slave *slv, struct logfile *l, ssize_t max_send_bytes, ssize_t stop_at)
{
	int32_t r;
	uint32_t rows_in_e, max_send_rows;
	struct logfile_entry *e;

	/* read enough rows from l to fill the client's send buffer, and
	 * send them off */

	max_send_rows = max_send_bytes / sizeof(struct logfile_entry);
	e = alloca(max_send_rows * sizeof(struct logfile_entry));

	r = logfile_read(l, e, max_send_rows);
	if (r == -1)
	{
		logmsg_f(LOG_CRIT, "logfile_read returned -1");
		return -1;
	}
	if (r % sizeof(struct logfile_entry))
	{
		logmsg_f(LOG_CRIT, "short logfile_read, got %d bytes", r);
		return -1;
	}
	rows_in_e = r / sizeof(struct logfile_entry);

	return client_slave_send_rows_from_buf(slv, e, rows_in_e, stop_at);
}

int32_t client_slave_open_log(struct slave *slv, struct logfile *l)
{
	/* check log_file exists and is at least log_pos bytes long */
	if (-1 == logfile_open(l, slv->log_file, O_RDONLY))
	{
		/* log probably doesn't exist or is invalid */
		sockwrite(slv->fd, RESPONSE_510);
		return -1;
	}

	/* log_pos is the byte offset of the logfile to send next */
	if (-1 == logfile_seek_to_byte(l, slv->log_pos))
	{
		/* logfile isn't this big */
		logfile_close(l);
		sockwrite(slv->fd, RESPONSE_511);
		return -1;
	}

	return 0;
}

int32_t client_slave_do_log(struct slave *slv, struct logfile *l, ssize_t stop_at)
{
	int32_t r, kq_write;
	ssize_t log_size;
	struct kevent kev;

	kq_write = kqueue();

	/* see when we can write to the client */
	EV_SET(&kev, slv->fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, NULL);
	r = kevent(kq_write, &kev, 1, NULL, 0, NULL);

	log_size = logfile_get_size(l);

	while (slv->log_pos < log_size)
	{
		if (slv->stop_replicating)
		{
			close(kq_write);
			return E_CLIENT_SLAVE_STOP;
		}

		//logmsg(LOG_DEBUG, "pos=%d size=%d", slv->log_pos, log_size); 

		if (stop_at && slv->log_pos == stop_at)
		{
			logmsg_f(LOG_DEBUG, "reached stop_at");
			break;
		}

		/* wait for client to be ready */
		//logmsg(LOG_DEBUG, "waiting for client..");
		r = kevent(kq_write, NULL, 0, &kev, 1, NULL);

		/* don't send anything to the client unless they have room
		 * for at least one complete logrow */
		if ((unsigned int)kev.data < sizeof(struct logfile_entry))
		{
			logmsg(LOG_WARNING, "fd=%d slave write buffer full", slv->fd);
			sleep(1);
			continue;
		}

		if (client_slave_read_and_send_rows(slv, l, kev.data, stop_at))
		{
			logmsg_f(LOG_ERR, "client_slave_read_and_send_rows error");
			close(kq_write);
			return -1;
		}

		/* slv->log_pos is updated inside client_slave_send_rows */
	}
	logmsg_f(LOG_NOTICE, "slave fd=%d finished log %s", slv->fd, l->basename);

	close(kq_write);

	return 0;
}

int32_t client_slave_catchup(struct slave *slv,
    char *current_log_file, ssize_t current_log_pos)
{
	int32_t r;
	struct logfile l;
	ssize_t stop_at;
	
	/* open first log */
	if (client_slave_open_log(slv, &l))
		return -1; /* error sent in function */

	while(l.fd)
	{
		if (current_log_file && !strcmp(l.basename, current_log_file))
		{
			/* this log is currently being written to, so only
			 * catchup until current_log_pos, then stop */
			stop_at = current_log_pos;
		}
		else
			stop_at = 0;

		/* send all rows in this log, while watching for commands */
		r = client_slave_do_log(slv, &l, stop_at);
		if (r)
		{
			logfile_close(&l);
			return r; /* return all abnormal conditions */
		}

		/* done with that log, move to the next one */
		r = logfile_move_to_next(&l);
		if (r == 0)
		{
			strcpy(slv->log_file, l.basename);
			slv->log_pos = logfile_fixup_byte_offset(0);
			logfile_seek_to_byte(&l, slv->log_pos);
		}
		else if (r == E_LOGMOVE_NO_MORE_LOGS)
			break; /* no more logs */
		else
		{
			logmsg_f(LOG_ERR,
			    "logfile_move_to_next unexpected error");
			return -1;
		}
	}

	logmsg_f(LOG_NOTICE, "slave fd=%d done with catchup", slv->fd);

	return 0;
}

void client_slave_disconnecting(struct slave *slv)
{
	slv->fd = 0;
}

void *be_a_slave_cmd_reader(void *arg)
{
	int32_t l;
	char *p, buf[SOCK_BUFSIZE];
	struct slave *slv = arg;

	logmsg_f(LOG_NOTICE, "slave fd=%d starting up", slv->fd);

	/* our job is simply to wait in read() on slv->fd and process
	 * incoming data as commands from a connected slave */
	while((l = recv(slv->fd, buf, SOCK_BUFSIZE, 0)) > 0)
	{
		if ((p = strchr(buf, '\n'))) *p = 0x0;
		if ((p = strchr(buf, '\r'))) *p = 0x0;
		buf[l] = 0x0;

#if DEBUG_LOG_TRAFFIC
		logmsg(LOG_DEBUG, "fd=%d [slv] << %s", fd, buf);
#endif

		if (!strncasecmp(buf, "stop", 4))
		{
			/* slave wants to stop replication */
			/* all done outside loop; that way we handle the
			 * client just disconnecting too */
			break;
		}

		else
		{
			sockwrite(slv->fd, RESPONSE_500);
		}
	}

	slv->in_live_replication = false;
	slv->stop_replicating = true;
	queue_enq(slv->incoming_rows, NULL);

	logmsg_f(LOG_NOTICE, "slave fd=%d shutting down", slv->fd);

	return NULL;
}

int32_t client_slave_catchup_wrapper(struct slave *slv)
{
	int32_t r;
	char *current_log_file;
	ssize_t current_log_pos;

	/* the first call to client_slave_catchup() does all logs from the
	 * slaves requested position up to the last log entry we have written */
	logmsg_f(LOG_DEBUG, "catchup phase 1 for slave %s [fd=%d]", slv->id, slv->fd);
	if ((r = client_slave_catchup(slv, NULL, 0)))
	{
		/* stop on any abnormal condition */
		return -1;
	}

	/* after that, we request live updates and at the same time get the
	 * current logfile/position */
	if (-1 == logfile_add_slave(g->l, slv, &current_log_file, &current_log_pos))
	{
		return -1;
	}

	/* now play catchup again, but only up to the current file/position */
	logmsg_f(LOG_DEBUG,
	    "catchup phase 2 for slave %s [fd=%d]; %s:%d to %s:%d",
	    slv->id, slv->fd, slv->log_file, slv->log_pos,
	    current_log_file, current_log_pos);
	if ((r = client_slave_catchup(slv, current_log_file, current_log_pos)))
	{
		/* stop on any abnormal condition */
		return -1;
	}

	/* catchup completed and now ready to go live */
	return 0;
}

void client_do_slave(struct client *self, const char *sbuf)
{
	/* the client wants to be a replication slave */

	const char *p = sbuf;
	uint32_t i;
	int32_t r;
	ssize_t new_log_pos, log_pos;
	char server_id[128], log_file[128];
	struct slave *slv = g->slaves;
	pthread_t thread_read_commands;

	/* SLAVE <server_id> <log_row_id> */
	if (3 != sscanf(p, "%128s %128s %lu", server_id, log_file, &log_pos))
	{
		sockwrite(self->client_fd, RESPONSE_507);
		return;
	}

	logmsg(LOG_NOTICE, "client fd=%d (id=%s) is becoming a slave at %s:%lu",
	    self->client_fd, server_id, log_file, log_pos);

	/* check if this slave is already connected */
	for (i = 0 ; i < MAX_MSGIDDBDS_CONNECTED ; i++)
	{
		slv = &g->slaves[i];

		if (slv->fd == 0)
			continue; /* no slave */

		if (strcmp(slv->id, server_id))
			continue; /* a different slave */

		/* we already have a slave with this id connected */
		sockwrite(self->client_fd, RESPONSE_506);
		return;
	}

	/* add this slave into g->slaves */
	for (i = 0 ; i < MAX_MSGIDDBDS_CONNECTED ; i++)
	{
		slv = &g->slaves[i];

		if (slv->fd)
			continue; /* slot used */

		i = MAX_MSGIDDBDS_CONNECTED + 1;
		break;
	}

	if (i != MAX_MSGIDDBDS_CONNECTED + 1)
	{
		/* didn't find a free slot to put the slave in */
		logmsg_f(LOG_CRIT, "g->slaves has no free space!");
		sockwrite(self->client_fd, RESPONSE_508);
		return;
	}

	/* success */
	strcpy(slv->id, server_id);
	slv->in_live_replication = false;
	slv->stop_replicating = false;
	slv->fd = self->client_fd;

	strcpy(slv->log_file, log_file);
	slv->log_pos = log_pos;

	if (slv->incoming_rows == NULL)
		slv->incoming_rows = queue_init();

	new_log_pos = logfile_fixup_byte_offset(slv->log_pos);
	if (new_log_pos != slv->log_pos)
	{
		logmsg(LOG_WARNING,
		    "client fd=%d (%s) wanted pos=%lu, corrected to %lu",
		    slv->fd, server_id, slv->log_pos, new_log_pos);
		slv->log_pos = new_log_pos;
	}

	/* spawn a second per-client thread to read slave responses. It will
	 * fill in slv->cmd with anything read that this thread has to deal
	 * with (for now, pretty much just "stop" */
	if (pthread_create(&thread_read_commands, NULL,
	    be_a_slave_cmd_reader, slv))
	{
		logmsg_f(LOG_CRIT, "pthread_create error");
		sockwrite(slv->fd, RESPONSE_508);
		return;
	}

	sockwrite(slv->fd, RESPONSE_210, slv->log_file, slv->log_pos);
	
	if (client_slave_catchup_wrapper(slv))
	{
		/* something failed in catchup replication */
		goto stop_replicating;
	}


	/* now we're into realtime replication */

	r = 0;
	struct logfile_replicate *lr;
	while((lr = queue_deq(slv->incoming_rows)))
	{
		/* if we're into a new logfile, update this slv struct */
		/* FIXME: unnecessarily copying strings about :( */
		strcpy(slv->log_file, lr->log_file);

		/* slv->log_pos *should* already be right, but make sure */
		slv->log_pos = lr->log_pos;

		/* slv->log_pos is also updated inside client_slave_send_rows */
		r = client_slave_send_rows_from_buf(slv, lr->rows, lr->row_count, 0);
		/* r is checked after the slv_remaining_count stuff */

		/* atomically decrement slv_remaining_count */
		pthread_mutex_lock(&lr->LOCKED);
		if (--lr->slv_remaining_count == 0)
		{
			/* we were the last slave to do these rows */
			pthread_mutex_unlock(&lr->LOCKED);
			pthread_mutex_destroy(&lr->LOCKED);
			free(lr->rows);
			free(lr);
		}
		else
			pthread_mutex_unlock(&lr->LOCKED);

		if (r)
		{
			logmsg_f(LOG_ERR, "client_slave_send_rows_from_buf error");
			break;
		}
	}

	/* be_a_slave_cmd_reader will push NULL at us to signify that the
	 * slave wants to stop */
	if (!lr)
		r = E_CLIENT_SLAVE_STOP;

stop_replicating:
	switch(r)
	{
		default: /* client_slave_catchup return codes mostly */
		sockwrite(slv->fd, RESPONSE_520);
		break;

		case E_CLIENT_SLAVE_STOP:
		sockwrite(slv->fd, RESPONSE_211);
		break;
	}

	/* reap the command reading thread to avoid a leak */
	pthread_join(thread_read_commands, NULL);

	/* there is no guarantee that slv->in_live_replication will be set
	 * to false and the logfile commiter will see it before our NULL was
	 * pushed into the incoming_rows queue. Therefore, there may be
	 * leftover rows in this queue even now; if there are, throw them
	 * away, remembering to keep on cleaning up as we go..
	*/
	while(!queue_empty(slv->incoming_rows))
	{
		if ((lr = queue_deq(slv->incoming_rows)))
		{
			/* FIXME: code duplication from above; but we still
			 * have to clean up after ourselves */
			pthread_mutex_lock(&lr->LOCKED);
			if (--lr->slv_remaining_count == 0)
			{
				/* we were the last slave to do these rows */
				pthread_mutex_unlock(&lr->LOCKED);
				pthread_mutex_destroy(&lr->LOCKED);
				free(lr->rows);
				free(lr);
			}
			else
				pthread_mutex_unlock(&lr->LOCKED);
		}
	}

	client_slave_disconnecting(slv);
	return;
}

void client_do_check(struct client *self, const char *sbuf)
{
	(void)self;

	/* CHECK <fileid> */

	fileid_t fileid = atol(sbuf);
	struct dat_files *d;

	/* see if we need to open the table? */
	if ((d = get_table_for_fileid(fileid, 0)) == NULL)
	{
		sockwrite(self->client_fd, RESPONSE_404, fileid);
		return;
	}
	
	/* lock the table */
	table_lock(d, T_WRLOCK);

	/* check */
	table_check(d);

	/* unlock */
	table_unlock(d);

	sockwrite(self->client_fd, RESPONSE_206);
	return;
}

int handle_a_client(void *arg)
{
	struct client *self = (struct client *)arg;
	int32_t l;
	fd_t fd = self->client_fd;
	char *p, buf[SOCK_BUFSIZE];

	/* allocated on first PUT */
	self->logbuf = NULL;

	/* standard greeting, change if we're down etc */
	sockwrite(fd, "200 Hello, this is msgidDBd v%s, built %s",
	    MSGIDDBD_VERSION, __TIMESTAMP__);

	//logmsg_f(LOG_INFO, "fd=%d connecting", fd);

	while((l = recv(fd, buf, SOCK_BUFSIZE, 0)) > 0)
	{
		if ((p = strchr(buf, '\n'))) *p = 0x0;
		if ((p = strchr(buf, '\r'))) *p = 0x0;
		buf[l] = 0x0;

#if DEBUG_LOG_TRAFFIC
		logmsg(LOG_DEBUG, "fd=%d << %s", fd, buf);
#endif

		if (!strncasecmp(buf, "stats", 5))
			client_do_stats(self, buf+6);

		else if (!strncasecmp(buf, "get", 3))
			client_do_get(self, buf+4);

		else if (!strncasecmp(buf, "put_checkdupe", 13))
			client_do_put(self, buf+14, PUT_CHECKDUPE);

		else if (!strncasecmp(buf, "put", 3))
			client_do_put(self, buf+4, PUT_NOFLAGS);

		else if (!strncasecmp(buf, "commit", 6))
			client_do_commit(self, buf+7);

		else if (!strncasecmp(buf, "slave", 5)) /* another msgiddbd */
			client_do_slave(self, buf+6);

		else if (!strncasecmp(buf, "check", 5)) /* check table */
			client_do_check(self, buf+6);

		else if (!strncasecmp(buf, "quit", 4))
			break;

		else if (!strncasecmp(buf, "diediedie", 9))
		{
			g->time_to_die = true;
			pthread_kill(threads.listener, SIGUSR1);
			sockwrite(fd, RESPONSE_290);
		}

		else
		{
			sockwrite(fd, RESPONSE_500);
		}
	}

	if (l < 0)
		logmsg_f(LOG_ERR, "read: %s", STR_errno);

	/* uncomment for an implicit commit when a client disconnects */
	//client_do_commit(self, buf);

	/* standard goodbye */
	sockwrite(fd, RESPONSE_299);

	close(fd);
	//logmsg_f(LOG_INFO, "fd=%d disconnected", fd);

	atomic_dec_32(g->open_clients);

	if (self->logbuf)
	{
		if (logfile_buffer_free(self->logbuf) == E_LOGBUFFREE_NOT_EMPTY)
			logmsg_f(LOG_WARNING,
			    "fd=%d did not commit some rows!", fd);

		self->logbuf = NULL;
	}

	return 0;
}

void *be_a_client_handler(void *arg)
{
	/* we are spawned from main() and we should sit and wait on incoming
	 * client fds in the Queue g->incoming_clients */
	struct child_info *self = arg;

	struct client *c;

	atomic_inc_32(g->client_handler_count);

	logmsg_f(LOG_NOTICE, "starting up (new client_handler_count=%d)",
	    g->client_handler_count);

	while ((c = queue_deq(g->incoming_clients)))
	{
		handle_a_client(c);
		free(c);
	}

	atomic_dec_32(g->client_handler_count);

	logmsg_f(LOG_NOTICE, "shutting down (new client_handler_count=%d)",
	    g->client_handler_count);

	queue_enq(g->threads_to_reap, self);

	return NULL;
}
