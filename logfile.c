#include "includes.h"
#include "defines.h"

#include "msgiddbd.h"
#include "misc.h"
#include "logmsg.h"
#include "table.h"
#include "logfile.h"

#include "thrqueue.h"


extern struct ShareData *g;

int32_t logfile_init_struct(struct logfile **l)
{
	*l = safe_calloc(sizeof(struct logfile));
	(*l)->fd = 0; /* indicates there is no log open yet */
	pthread_mutex_init(&(*l)->LOCKED, NULL);

	return 0;
}

int32_t logfile_free_struct(struct logfile **l)
{
	pthread_mutex_destroy(&(*l)->LOCKED);
	free(*l);
	return 0;
}

int32_t logfile_create(struct logfile *l)
{
	/* open a new logfile and return a filled in struct */

	/* logfile = log_%d.log
	 * 
	 * where %d is the time the log was created
	 */
	
	time_t now = time(NULL);
	char filename[PATH_MAX], filename_base[PATH_MAX];

	/* clean up existing fd's so we're in a known state */
	l->fd = 0;

	sprintf(filename, "%s/logs/log_%lu.log", g->cfg.dbroot, now);

	logmsg_f(LOG_NOTICE, "creating %s", filename);

	l->fd = open(filename, O_RDWR | O_CREAT | O_APPEND, (mode_t)0644);
	if (l->fd == -1)
	{
		logmsg_f(LOG_ERR, "open: %s", STR_errno);
		l->fd = 0;
		return -1;
	}

	/* resize to one page and mmap in as a logfile_header */
	if (ftruncate(l->fd, PAGE_SIZE))
	{
		logmsg_f(LOG_ERR, "ftruncate: %s", STR_errno);
		close(l->fd);
		l->fd = 0;
		return -1;
	}

	l->m = mmap(NULL, PAGE_SIZE, PROT_RW, MAP_SHARED, l->fd, 0);
	if (l->m == MAP_FAILED)
	{
		logmsg_f(LOG_ERR, "mmap header: %s", STR_errno);
		close(l->fd);
		l->fd = 0;
		return -1;
	}

	basename_r(filename, filename_base);
	l->basename = strdup(filename_base);

	l->h = (struct logfile_header *)l->m;

	/* initialise this new header */
	l->h->file_magic   = LOGFILE_HEADER_MAGIC;
	l->h->file_version = LOGFILE_HEADER_CURRENT_VERSION;

	l->h->row_count    = 0; /* empty so far */

	l->h->flags        = 0;
	l->h->flags       |= LOGFILE_HEADER_FLAG_OPEN;

	/* seek to the end of the log, so the file pointer is right even
	 * before any rows actually get appended (logfile_add_slave can use
	 * this, without this lseek it would return 0 before any rows are
	 * commited) */
	if (lseek(l->fd, PAGE_SIZE, SEEK_SET) == -1)
	{
		logmsg_f(LOG_CRIT, "lseek: %s", STR_errno);
		close(l->fd);
		l->fd = 0;
		return -1;
	}

	logmsg_f(LOG_NOTICE, "%s created [fd=%d]", l->basename, l->fd);

	/* now we're ready to start appending to l->fd */

	return 0;
}

int32_t logfile_sync(struct logfile *l)
{
	if (! l || ! l->fd)
		return -1;

	if (l->mode == O_RDONLY)
		return 0;

	return fsync(l->fd);
}

int32_t logfile_close(struct logfile *l)
{
	if (! l || ! l->fd) return 0; /* wasn't opened */

	logmsg_f(LOG_NOTICE, "closing %s [fd=%d]", l->basename, l->fd);

	/* a flag to say the log was cleanly closed */
	if (l->mode != O_RDONLY && l->h->flags & LOGFILE_HEADER_FLAG_OPEN)
		l->h->flags &= ~(LOGFILE_HEADER_FLAG_OPEN);

	munmap(l->m, PAGE_SIZE);

	logfile_sync(l);

	close(l->fd);
	l->fd = 0;

	free(l->basename);
	l->basename = NULL;

	return 0;
}

int32_t logfile_open(struct logfile *l, char *filename, uint32_t mode)
{
	/* open an existing logfile and return a filled in struct */
	/* this is used for slave replication and log replays */

	/* mode is O_RDONLY / O_RDWR */
	int32_t mmap_mode = (mode == O_RDONLY) ? PROT_READ : PROT_RW;


	char buf[PATH_MAX], filename_base[PATH_MAX];

	/* ensure we have a full path - this works whether we were passed a
	 * relative or an absolute filename, see basename_r() */
	basename_r(filename, filename_base);
	snprintf(buf, PATH_MAX, "%s/logs/%s", g->cfg.dbroot, filename_base);

	l->basename = strdup(filename_base);

	if (-1 == (l->fd = open(buf, mode)))
	{
		logmsg_f(LOG_ERR, "open: %s", STR_errno);
		return -1;
	}
	l->mode = mode;

	l->m = mmap(NULL, PAGE_SIZE, mmap_mode, MAP_SHARED, l->fd, 0);
	if (l->m == MAP_FAILED)
	{
		logmsg_f(LOG_ERR, "mmap: %s", STR_errno);
		goto fail_close_files;
	}

	l->h = (struct logfile_header *)l->m;

	if (l->h->file_magic != LOGFILE_HEADER_MAGIC)
	{
		logmsg_f(LOG_ERR, "header magic not found");
		goto fail_close_files;
	}

	logmsg_f(LOG_NOTICE, "%s: opened, version=%d flags=%d rows=%lu applied=%lu [fd=%d, %s]",
	    l->basename, l->h->file_version, l->h->flags,
	    l->h->row_count, l->h->row_applied,
	    l->fd, (l->mode == O_RDONLY) ? "ro" : "rw");

	if (l->h->flags & LOGFILE_HEADER_FLAG_OPEN)
	{
		/* logfile was not cleanly closed! */
		logmsg_f(LOG_WARNING,
		    "%s already marked open", filename);
		return E_LOGOPEN_WAS_OPEN;
	}

	/* should we set logfile open here? this function is only used for
	 * logfile_replays (might update row_applied) and slave replication
	 * (no writes at all)
	*/

	/* success */
	return 0;

fail_close_files:
	if (l->basename) free(l->basename);
	l->basename = NULL;
	if (l->fd) close(l->fd);
	l->fd = 0;
	return -1;

}

int32_t logfile_open_if_diff(struct logfile *l, char *filename, uint32_t mode)
{
	/* simple wrapper around logfile_open that only performs then open
	 * if l wasn't already open with filename */

	if (l && l->fd)
	{
		/* FIXME: strcmp is slow, this could be improved */
		if (!strcmp(l->basename, filename))
			return 0; /* same log */
		else
		{
			/* different log, close the old one */
			logfile_close(l);
		}
	}

	return logfile_open(l, filename, mode);
}

int64_t logfile_get_size(struct logfile *l)
{
	/* return the size in bytes of the given logfile */
	struct stat sb;

	if (! l || ! l->fd)
		return -1;

	fstat(l->fd, &sb);

	return sb.st_size;
}

int64_t logfile_fixup_byte_offset(off_t offset)
{
	off_t t;

	/* correct a log_pos that doesn't map to the start of a logfile_entry */
	if ((t = ((offset - PAGE_SIZE) % sizeof(struct logfile_entry))))
		offset -= t;

	/* correct a log_pos of <4096 to 4096; the first 4k of a logfile is
	 * reserved for header information and a client doesn't want that;
	 * they want the first real row which is at offset 4096 */
	if (offset < PAGE_SIZE)
		offset = PAGE_SIZE;

	return offset;
}

char *logfile_get_current_name(struct logfile *l)
{
	if (! l || ! l->fd)
		return NULL;

	return l->basename;
}

off_t logfile_get_current_byte(struct logfile *l)
{
	if (! l || ! l->fd)
		return -1;

	return lseek(l->fd, 0, SEEK_CUR);
}

int64_t logfile_seek_to_byte(struct logfile *l, off_t offset)
{
	struct stat sb;
	off_t new_offset;

	if (! l || ! l->fd)
		return -1;

	fstat(l->fd, &sb);
	if (sb.st_size < offset)
		return -1;

	offset = logfile_fixup_byte_offset(offset);

	new_offset = lseek(l->fd, offset, SEEK_SET);
	if (new_offset == -1)
	{
		logmsg_f(LOG_ERR, "lseek: %s", STR_errno);
		return -1;
	}

	return 0;
}

int32_t logfile_seek_to_row(struct logfile *l, log_count_t row)
{
	/* this simply calls logfile_seek_to_byte with a modified offset */
	return logfile_seek_to_byte(l,
	    PAGE_SIZE + (sizeof(struct logfile_entry) * row));
}

int32_t logfile_read(struct logfile *l, struct logfile_entry *e, int32_t e_rows)
{
	/* read from the current offset into e, until eof or e is full
	 * (e_rows * sizeof(struct logfile_entry))
	*/

	if (! l || ! l->fd)
		return -1;

	return read(l->fd, e, e_rows * sizeof(struct logfile_entry));
}

int32_t logfile_add_slave(struct logfile *l, struct slave *slv, char **log_file, ssize_t *log_pos)
{
	/* fd is a slave who is interested in all further PUTs */

	if (pthread_mutex_lock(&l->LOCKED))
	{
		logmsg_f(LOG_CRIT, "pthread_mutex_lock: %s", STR_errno);
		return -1;
	}

	/* mark the slave as wanting live queries */
	slv->in_live_replication = true;

	/* return the current position; slaving function uses this so it
	 * knows when to stop doing catchup */
	if (l && l->fd)
	{
		*log_file = logfile_get_current_name(g->l);
		*log_pos  = logfile_get_current_byte(g->l);

		if (!*log_file || *log_pos == -1)
		{
			/* this shouldn't happen */
			logmsg_f(LOG_ERR,
			    "logfile_get_current_* returned unexpected error");
			pthread_mutex_unlock(&l->LOCKED);
			return -1;
		}
	}

	/* if no logfile open.. */
	else
	{
		*log_file = NULL;
		*log_pos = 0;
	}

	if (pthread_mutex_unlock(&l->LOCKED))
	{
		logmsg_f(LOG_CRIT, "pthread_mutex_unlock: %s", STR_errno);
		return -1;
	}

	return 0;
}

int32_t logfile_commit(struct logfile *l,struct logfile_buffer *b,int8_t flags)
{
	int32_t w, t_w;
	uint64_t i;
	off_t log_pos;
	struct slave *slv;
	struct logfile_entry *e;
	struct logfile_replicate *r;
#if SPAM_COMMIT_TIMES
	uint64_t start = get_time_usec();
#endif

	int8_t get_lock = flags & LOG_COMMIT_GET_LOCK;

	if (! l || ! l->fd || ! b || ! b->used)
		return 0; /* nothing to do */

	if (get_lock && pthread_mutex_lock(&l->LOCKED))
	{
		logmsg_f(LOG_CRIT, "pthread_mutex_lock: %s", STR_errno);
		return -1;
	}

	log_pos = logfile_get_current_byte(l);

	t_w = b->used * sizeof(struct logfile_entry);
	w = write(l->fd, b->buf, t_w);
	if (w != t_w)
	{
		logmsg_f(LOG_ERR, "short write: %s", STR_errno);
		if (get_lock) pthread_mutex_unlock(&l->LOCKED);
		return -1;
	}

	/* update logfile header */
	l->h->row_count += b->used;

	/* ensure the logfile is updated on disk too */
	if (logfile_sync(l))
	{
		logmsg_f(LOG_ERR, "logfile_sync/1 error");
		if (get_lock) pthread_mutex_unlock(&l->LOCKED);
		return -1;
	}

	/* replicate the queries; here we just push a notification that x
	 * rows from logfile l at position p have been written;
	 * be_a_replication_master thread will do the rest */
	r = safe_malloc(sizeof(struct logfile_replicate));
	r->slv_count = 0;
	for (i = 0 ; i < MAX_MSGIDDBDS_CONNECTED ; i++)
	{
		slv = &g->slaves[i];
		if (slv->fd && slv->in_live_replication)
			r->slvs[r->slv_count++] = slv;
	}

	if (r->slv_count)
	{
		strcpy(r->log_file, l->basename);
		r->log_pos = log_pos;
		r->row_count = b->used;

		/* pass to be_a_replication_master */
		queue_enq(g->replicated_log_entries, r);
	}
	else
	{
		/* no slaves are interested in this */
		free(r);
	}

	/* now execute all the updates contained in buf before we delete it */
	for (i = 0 ; i < b->used ; i++)
	{
		e = (struct logfile_entry *)b->buf + i;
		if (-1 == add_segment(&e->d))
		{
			if (get_lock) pthread_mutex_unlock(&l->LOCKED);
			return -1;
		}
	}

	/* sync all tables */
	if (tables_sync())
	{
		logmsg_f(LOG_ERR, "tables_sync error");
		if (get_lock) pthread_mutex_unlock(&l->LOCKED);
		return -1;
	}

	/* inform the logfile header that these rows have been applied */
	l->h->row_applied += b->used;
	if (logfile_sync(l))
	{
		logmsg_f(LOG_ERR, "logfile_sync/2 error");
		if (get_lock) pthread_mutex_unlock(&l->LOCKED);
		return -1;
	}

	/* check if we're ready to rotate this log out */
	if (l->h->row_count > LOGFILE_ROTATE_COUNT)
	{
		logfile_close(l);

		/* the next PUT will automatically open a new one */
	}

	/* empty the buffer for re-use */
	b->used = 0;

	if (get_lock && pthread_mutex_unlock(&l->LOCKED))
	{
		logmsg_f(LOG_CRIT, "pthread_mutex_unlock: %s", STR_errno);
		return -1;
	}

#if SPAM_COMMIT_TIMES
	logmsg(LOG_DEBUG, "Commit done, took %.4fs to commit %lu items",
	    (get_time_usec() - start)/1000000.0, i);
#endif

	return 0;
}

int32_t logfile_move_to_next(struct logfile *l)
{
	DIR *dfd;
	char *p;
	time_t t, old_log_time, next_log_candidate = UINT_MAX;
	struct dirent *de;
	char dirname[PATH_MAX], filename[PATH_MAX];

	/* get the time component of the current log */
	p = strchr(l->basename, '_');
	if (!p) return -1;
	old_log_time = atol(++p);


	/* close logfile l; this only fails if fsync() fails */
	logfile_close(l);


	/* now scan the logdir for the next logfile. this will be the file
	 * which has the next highest timestamp than the one we just had
	 *
	*/
	sprintf(dirname, "%s/logs", g->cfg.dbroot);
	dfd = opendir(dirname);

	while ((de = readdir(dfd)) != NULL)
	{
		p = strchr(de->d_name, '_');
		if (!p) continue;
		t = atol(++p);

		//logmsg(LOG_DEBUG, "got a t of %lu", t);

		if (t > old_log_time)
		{
			/* this is a candidate for next log */
			next_log_candidate = MIN(next_log_candidate, t);
		}
	}
	closedir(dfd);

	//logmsg(LOG_DEBUG, "next_log_candidate %lu", next_log_candidate);

	if (next_log_candidate == UINT_MAX)
	{
		/* no more logs */
		return E_LOGMOVE_NO_MORE_LOGS;
	}

	sprintf(filename, "%s/logs/log_%lu.log", g->cfg.dbroot, next_log_candidate);

	logfile_open(l, filename, O_RDONLY);

	return 0;
}

struct logfile_buffer *logfile_buffer_alloc(int32_t size)
{
	struct logfile_buffer *b;

	b = safe_calloc(sizeof(struct logfile_buffer));
	b->used = 0;
	b->size = size;

	b->buf = safe_calloc(sizeof(struct logfile_entry) * b->size);

	return b;
}
int32_t logfile_buffer_free(struct logfile_buffer *b)
{
	int32_t r = 0;

	/* warn about non-empty log buffers when freeing them */
	if (b->used > 0)
	{
		r = E_LOGBUFFREE_NOT_EMPTY;
		logmsg_f(LOG_WARNING,
		    "freeing a logfile_buffer with %d uncommitted rows!",
		    b->used);
	}

	free(b->buf);
	free(b);

	return r;
}

int32_t logfile_write_row(struct logfile *l, struct logfile_buffer *buf, struct logfile_entry *e)
{
	struct logfile_entry *p;

	e->date  = time(NULL);
	e->magic = LOGFILE_ENTRY_MAGIC;

	if (pthread_mutex_lock(&l->LOCKED))
	{
		logmsg_f(LOG_CRIT, "pthread_mutex_lock: %s", STR_errno);
		return -1;
	}

	/* buffer rows rather than call write() lots */

	if (buf->size == LOGFILE_BUFFER_SIZE && buf->used == buf->size)
	{
		//logmsg(LOG_WARNING,
		//    "logfile_write_row: forcing commit because logfile buffer is full");
		logfile_commit(l, buf, LOG_COMMIT_NO_FLAGS); /* no lock */
	}

	p = (struct logfile_entry *)buf->buf + buf->used;
	memcpy(p, e, sizeof(struct logfile_entry));
	buf->used++;

	if (pthread_mutex_unlock(&l->LOCKED))
	{
		logmsg_f(LOG_CRIT, "pthread_mutex_unlock: %s", STR_errno);
		return -1;
	}

	return 0;
}

/* replay the given logfile, checking if entries in it are in our database. */
int32_t logfile_replay(struct logfile *l)
{
	int32_t b;
	struct logfile_entry e;
	log_count_t applied = 0;

	if (l->h->row_applied == l->h->row_count)
	{
		/* everything in this log has been applied */
		return 0;
	}

	if (logfile_seek_to_row(l, l->h->row_applied) == -1)
		return -1;
	
	/* read an entry */
	while((b = logfile_read(l, &e, 1)))
	{
		if (b != sizeof(struct logfile_entry))
		{
			/* short read! this isn't right. probably corrupt
			 * logfile, abort */
			logmsg_f(LOG_CRIT, "short read (got %d bytes)", b);
			return -1;
		}

		if (e.magic != LOGFILE_ENTRY_MAGIC)
		{
			logmsg_f(LOG_CRIT, "missing logfile_entry magic!");
			abort();
		}

		/* check if we have this segment */
		if (find_segment(&e.d))
		{
			/* segment was in the db after all. update
			 * row_applied so we hopefully don't end up doing
			 * this row again. sync here isn't critical, if we
			 * crash AGAIN before it's synced, we're just
			 * duplicating replay work. oh well. */
			l->h->row_applied++;
			continue; /* next row! */
		}

		/* we need to add the row to the database. DO NOT log it! */

		/* so just call add_segment */
		if (add_segment(&e.d) == -1)
		{
			logmsg_f(LOG_ERR, "add_segment error");
			return -1;
		}

		/* do the logfile header updates ourselves. we'll add this
		 * into the logfile and sync it at the end, same as a normal
		 * logfile commit. */
		applied++;
	}

	/* log replay finished; sync everything */

	/* sync tables before we tell the log about new row_applied */
	if (tables_sync())
	{
		logmsg_f(LOG_ERR, "tables_sync error");
		return -1;
	}

	/* now we know we won't have to replay these again */
	l->h->row_applied += applied;
	if (logfile_sync(l))
	{
		/* fuck knows what's happened here :/ */
		logmsg_f(LOG_ERR, "logfile_sync error");
		return -1;
	}

	logmsg_f(LOG_NOTICE, "applied %d segments", applied);

	return 0;
}

int32_t logfile_check(char *filename)
{
	/* logfile is a fully pathed filename to open and check */
	/* if we find it's not cleanly closed, run a replay */

	int32_t r;
	struct logfile l;

	logmsg_f(LOG_NOTICE, "checking %s", filename);

	if (-1 == (r = logfile_open(&l, filename, O_RDWR)))
	{
		/* logfile failed to open */
		return -1;
	}

	/* check the header; if row_applied == row_count, there was
	 * nothing in the log to commit before the crash */
	if (l.h->row_applied == l.h->row_count)
	{
		/* good news, close the log and move on */
		logfile_close(&l);
		return 0;
	}

	logmsg_f(LOG_WARNING, "replaying %s", filename);

	/* time to replay */
	if (logfile_replay(&l))
	{
		logmsg_f(LOG_CRIT, "replay failed!");
		abort();
	}

	logmsg_f(LOG_NOTICE, "replay of %s complete", filename);

	logfile_close(&l);

	return 0;
}

int32_t logfile_check_all()
{
	DIR *dirp;
	struct dirent *de;
	char tmp[PATH_MAX];

	sprintf(tmp, "%s/logs", g->cfg.dbroot);
	if (!(dirp = opendir(tmp)))
	{
		logmsg_f(LOG_CRIT, "opendir: %s", STR_errno);
		return -1;
	}

	while ((de = readdir(dirp)))
	{
		if (!strstr(de->d_name, "log_")) continue;

		sprintf(tmp, "%s/logs/%s", g->cfg.dbroot, de->d_name);

		if (logfile_check(tmp))
		{
			closedir(dirp);
			return -1;
		}
	}

	closedir(dirp);

	return 0;
}
