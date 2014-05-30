#include "includes.h"
#include "defines.h"

#include "msgiddbd.h"
#include "misc.h"

#include "logmsg.h"

#include "table.h"
#include "logfile.h"

extern struct ShareData *g; /* global shared data */

ssize_t filesize(fd_t fd)
{
	struct stat sb;
	if (fstat(fd, &sb))
		return -1;

	return sb.st_size;
}

/* MurmurHash2 {{{ */
#ifdef X86
uint32_t MurmurHash2(const void * key, uint32_t len, uint32_t seed)
{
	// 'm' and 'r' are mixing constants generated offline.
	// They're not really 'magic', they just happen to work well.

	const uint32_t m = 0x5bd1e995;
	const int32_t r = 24;

	// Initialize the hash to a 'random' value

	uint32_t h = seed ^ len;

	// Mix 4 bytes at a time into the hash

	const unsigned char * data = (const unsigned char *)key;

	while(len >= 4)
	{
		uint32_t k = *(uint32_t *)data;

		k *= m; 
		k ^= k >> r; 
		k *= m; 
		
		h *= m; 
		h ^= k;

		data += 4;
		len -= 4;
	}
	
	// Handle the last few bytes of the input array

	switch(len)
	{
	case 3: h ^= data[2] << 16;
	case 2: h ^= data[1] << 8;
	case 1: h ^= data[0];
	        h *= m;
	};

	// Do a few final mixes of the hash to ensure the last few
	// bytes are well-incorporated.

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
} 
#else
// Neutral aligned implementation
uint32_t MurmurHash2(const void *key, uint32_t len, uint32_t seed)
{
	const uint32_t m = 0x5bd1e995;
	const int32_t r = 24;

	uint32_t h = seed ^ len;

	const unsigned char *data = (const unsigned char *)key;

	while(len >= 4)
	{
		uint32_t k;

		k  = data[0];
		k |= data[1] << 8;
		k |= data[2] << 16;
		k |= data[3] << 24;

		k *= m; 
		k ^= k >> r; 
		k *= m;

		h *= m;
		h ^= k;

		data += 4;
		len -= 4;
	}

	switch(len)
	{
		case 3: h ^= data[2] << 16;
		case 2: h ^= data[1] << 8;
		case 1: h ^= data[0];
		h *= m;
	};

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}
#endif
/* }}} */

/* given a struct dat_files, and fileid pointer into it, return the offset
 * in bytes at which we can find this fileid (for debugging prints mostly) */
uint64_t calc_file_offset(struct dat_files *d, struct fileid *f)
{
	return (char *)f - (char *)d->f.m;
}
/* same for segments in sdat */
uint64_t calc_segments_offset(struct dat_files *d, struct segments *ss)
{
	return (char *)ss - (char *)d->s.m;
}

int32_t check_segments_page(struct dat_files *d, struct segments *ss, bool tryfix)
{
	int32_t r = 0;
	uint32_t h;

	/* found myself doing this a lot; check both the magic and the hash
	 * for a segments page; if tryfix=true then try fixing it. */
	if (ss->magic != SEGMENTS_MAGIC)
	{
		r = -1;

		/* we have discovered a dodgy page :/ */
		logmsg_f(LOG_CRIT, "ss->magic invalid at offset %p! "
		    "(fileid=%lu(?), magic=%x)",
		    calc_segments_offset(d, ss), ss->fileid, ss->magic);
		if (tryfix)
		{
		//	table_nuke_segments_page(d, ss, f);
			r = 0;
		}

		/* no point checking hash if magic was wrong, we've either
		 * nuked the page or left it in indeterminate state */
		return r;
	}

	h = SEGMENTS_HASH(ss);
	if (ss->hash != h)
	{
		/* a half-written page maybe? */
		r = -1;

		logmsg_f(LOG_CRIT, "ss->hash invalid at offset %p! "
		    "(fileid=%lu(?), hash=%x wanted=%x)",
		    calc_segments_offset(d, ss), ss->fileid,
		    ss->hash, h);
		if (tryfix)
		{
			table_recover_segments_page(d, ss);
			r = 0;
		}
	}

	return r;
}


/* get_ inline functions {{{ */
inline struct fileid *get_files_offset(struct dat_file *f) /* {{{ */
{
	return (struct fileid *)(f->m + PAGE_SIZE);
} /* }}} */
inline struct segments *get_segments_offset(struct dat_file *s) /* {{{ */
{
	return (struct segments *)(s->m + PAGE_SIZE);
} /* }}} */
inline struct segments *get_segments_offset_for_page(struct dat_file *s, uint32_t p) /* {{{ */
{
	return (struct segments *)(s->m + (PAGE_SIZE*p));
} /* }}} */
inline struct segments *get_first_segments_for_file(struct dat_files *d, struct fileid *f) /* {{{ */
{
	if (f->first_segments > d->s.sh->segments_allocated)
	{
		logmsg_f(LOG_CRIT, "%s looks corrupt, fileid=%lu has "
		    "first_segments=%lu, but segments_allocated=%lu",
		    d->basename, f->fileid, f->first_segments,
		    d->s.sh->segments_allocated);
		return &sentinels.segment_page_out_of_bounds;
	}

	return (struct segments *)(&d->s.m[PAGE_SIZE * f->first_segments]);
} /* }}} */
inline struct segments *get_cur_segments_for_file(struct dat_files *d, struct fileid *f) /* {{{ */
{
	if (f->cur_segments > d->s.sh->segments_allocated)
	{
		logmsg_f(LOG_CRIT, "%s looks corrupt, fileid=%lu has "
		    "cur_segments=%lu, but segments_allocated=%lu",
		    d->basename, f->fileid, f->cur_segments,
		    d->s.sh->segments_allocated);
		return &sentinels.segment_page_out_of_bounds;
	}

	return (struct segments *)(&d->s.m[PAGE_SIZE * f->cur_segments]);
} /* }}} */
inline struct segments *get_next_segments(mmap_t s, struct segments *ss) /* {{{ */
{
	return ss->next_segments ?
	    (struct segments *)(&s[PAGE_SIZE * ss->next_segments]) : NULL;
} /* }}} */
inline struct segment *get_next_segment(struct segment *s) /* {{{ */
{
	return (struct segment *) ( (char *)s
	    + sizeof(struct segment) + s->msgid_len );
} /* }}} */
/* }}} */


struct fileid *add_fileid(struct dat_file *fdat, const fileid_t fileid)
{
	uint64_t n;
	struct fileid *f;

	/* check we're not overruning mmap_f - this should not happen now as
	 * we use fixed size .fdats; 100k files per fdat */
	if (fdat->fh->files_used == fdat->fh->files_allocated)
	{
		n = fdat->fh->files_allocated * 2;
		fdat_resize(n, fdat); /* updates fdat->fh->files_allocated */
	}
	
	f = &fdat->files[fileid - fdat->fh->fileid_min_req];

	f->fileid = fileid;

	fdat->fh->files_used++;

	if (fileid < fdat->fh->fileid_min)
		fdat->fh->fileid_min = fileid;

	if (fileid > fdat->fh->fileid_max)
		fdat->fh->fileid_max = fileid;

	return f;
}

int32_t table_lock_init(struct dat_files *d)
{
	int32_t e;

	if ((e = pthread_rwlock_init(&d->t_lock, NULL)))
	{
		logmsg_f(LOG_ERR, "pthread_rwlock_init: %s", strerror(e));
		return -1;
	}
	return 0;
}
int32_t table_lock_free(struct dat_files *d)
{
	return pthread_rwlock_destroy(&d->t_lock);
}
int32_t table_lock(struct dat_files *d, int8_t flags)
{
	int32_t e;

	if (flags & T_WRLOCK && (e = pthread_rwlock_wrlock(&d->t_lock)))
	{
		logmsg_f(LOG_ERR, "pthread_rwlock_wrlock: %s", strerror(e));
		return -1;
	}
	else if (flags & T_RDLOCK && (e = pthread_rwlock_rdlock(&d->t_lock)))
	{
		logmsg_f(LOG_ERR, "pthread_rwlock_rdlock: %s", strerror(e));
		return -1;
	}

	return 0;
}
int32_t table_unlock(struct dat_files *d)
{
	int32_t e;

	if ((e = pthread_rwlock_unlock(&d->t_lock)))
	{
		logmsg_f(LOG_ERR, "pthread_rwlock_unlock: %s", strerror(e));
		return -1;
	}

	return 0;
}


int32_t tables_sync()
{
	/* sync all open tables to disk */

	table_count_t i;
	struct dat_files *r;

	for(i = 0 ; i < g->t->dats_allocated ; i++)
	{
		r = &g->t->dats[i];
		if (r->f.fd) fsync(r->f.fd);
		if (r->s.fd)
		{
			fsync(r->s.fd);

			/* if the sdat was dirty, it's not now */
			if (r->s.sh->flags & SDAT_FLAGS_DIRTY)
				r->s.sh->flags &= ~(SDAT_FLAGS_DIRTY);
		}

	}

	return 0;
}


/* *dat resizing functions {{{ */
int32_t resize_mmaped_file(uint64_t newbytes, struct dat_file *d)
{
	/* resize the file to newbytes and make a new mmap */

	ssize_t oldbytes = filesize(d->fd);

	if (-1 == ftruncate(d->fd, newbytes))
	{
		logmsg_f(LOG_ERR, "ftruncate: %s", STR_errno);
		return -1;
	}

	/* FIXME: we need to lock this dat_file .. */

	munmap(d->m, oldbytes);

	d->m = mmap(NULL, newbytes, PROT_RW, MAP_SHARED, d->fd, 0);
	if (d->m == MAP_FAILED)
	{
		logmsg_f(LOG_CRIT, "mmap: %s", STR_errno);
		return -1;
	}

	return 0;
}
int32_t fdat_resize(uint64_t new_slots, struct dat_file *f)
{
	uint64_t newbytes = PAGE_SIZE + (sizeof(struct fileid) * new_slots);

	if (resize_mmaped_file(newbytes, f) == -1)
		return -1;

	/* always assume the mmap has moved */
	f->files = get_files_offset(f);

	/* always assume the mmap has moved */
	f->fh = (struct fdat_header *)f->m;

#if USE_M_LOCK
	/* update the size of m_lock too */
	f->m_lock = safe_realloc(f->m_lock, new_slots);
#endif

	f->fh->files_allocated = new_slots;

	return 0;
}
int32_t sdat_resize(uint64_t new_slots, struct dat_file *s)
{
	uint64_t newbytes = PAGE_SIZE + (PAGE_SIZE * new_slots);

	if (resize_mmaped_file(newbytes, s) == -1)
		return -1;

	/* do not include sdat mmaps in core files */
	madvise(s->m, newbytes, MADV_NOCORE);

	/* always assume the mmap has moved */
	s->sh = (struct sdat_header *)s->m;

	s->sh->segments_allocated = new_slots;

	return 0;
}
/* }}} */

int32_t table_nuke_fileid(struct dat_files *d, struct fileid *f,fileid_t fileid)
{
	/* an entire file is unrecoverable and must be nuked. generally,
	 * this means f->magic was wrong; if we can't trust that, we can't
	 * trust anything in the page? */
	(void)d; /* may come in useful someday */

	logmsg_f(LOG_CRIT, "DATALOSS: NUKING FDAT STRUCT FOR FILEID=%lu",
	    fileid);

	bzero(f, sizeof(struct fileid));

	return 0;
}

int32_t table_nuke_segments_page(struct dat_files *d, struct segments *ss)
{
	(void)d;

	/* blat the entire page. Set everything to zero. */
	bzero(ss, sizeof(struct segments));

	/* this leaves whatever fileid the segments page was for, with a
	 * broken chain of next_segments (or bad first_segments or
	 * cur_segments even). We'll deal with it later in
	 * table_repair_rebuild_fileid? */

	return 0;
}

int32_t table_recover_segments_page(struct dat_files *d, struct segments *ss)
{
	/* ss has an incorrect hash - see if we can work out which of the
	 * recently added segments caused it */
	(void)d;

	segment_count_t new_segment_count = 0;
	fileid_size_t hash_check_size = 0, this_segment_size = 0;
	struct segment *s;

	s = ss->segments;

	while(hash_check_size < ss->size_used)
	{
		new_segment_count++;
		this_segment_size = sizeof(struct segment) + s->msgid_len;
		hash_check_size += this_segment_size;

		if (ss->hash == MurmurHash2((char *)ss + sizeof(struct segments), hash_check_size, MURMURHASH_SEED))
		{
			logmsg_f(LOG_CRIT,
			    "DATALOSS: DROPPED %d BYTES OF SEGMENT DATA FROM FILEID=%lu!",
			    ss->size_used - hash_check_size, ss->fileid);

			/* we have found our last-known-good point */
			ss->size_used = hash_check_size;
			ss->segment_count = new_segment_count;
		}

		s = (struct segment *)((char *)ss->segments + hash_check_size);
	}

	return 0;
}

int32_t table_repair_rebuild_fileid(struct dat_files *d, struct fileid *f, fileid_t fileid)
{
	/* attempt to reconstruct the fileid struct pointed to by f, by
	 * scanning the sdat (in d->s) for matching fileid pages.
	 * fileid is passed separately because nothing in f
	 * (including f->fileid) can be trusted at this point.
	 * Do not start writing into f until we are sure we have something
	 * sane to put there.
	 * Do not read from f, at all.
	 */

	uint32_t h;
	page_off_t pageno;
	struct segments *ss, *prev_ss;

	/* we'll write into here, then memcpy it over when we're happy */
	struct fileid temp_f;

	logmsg_f(LOG_NOTICE, "attempting to rebuild fdat for fileid=%lu", fileid);

	/* basic stuff first */
	temp_f.fileid = fileid;
	temp_f.magic = FILEID_MAGIC;
	temp_f.page_alloc = 0;
	temp_f.first_segments = 0;

	/* for updating the previous next_segments when we find another page */
	prev_ss = NULL;

	/* start at the beginning (but skip s->sh, which would be pageno = 0) */
	for(pageno = 1 ; pageno < d->s.sh->segments_allocated ; pageno++)
	{
		ss = get_segments_offset_for_page(&d->s, pageno);

		/* technically neither of these should happen here, because
		 * we're called from table_check which has already
		 * sequentially checked the sdat. checking magic is cheap
		 * though, but we could comment out hash at some point */
		if (ss->magic != SEGMENTS_MAGIC)
		{
			/* we have discovered a dodgy page :/ */
			logmsg_f(LOG_CRIT, "ss->magic invalid at offset %p! "
			    "(fileid=%lu(?), magic=%x)",
			    calc_segments_offset(d, ss), ss->fileid, ss->magic);
			logmsg_f(LOG_NOTICE, "this shouldn't happen! "
			    "table_check should have found this");
			abort();
		}

		h = SEGMENTS_HASH(ss);
		if (ss->hash != h)
		{
			logmsg_f(LOG_CRIT, "ss->hash invalid at offset %p! "
			    "(fileid=%lu(?), hash=%x wanted=%x)",
			    calc_segments_offset(d, ss), ss->fileid,
			    ss->hash, h);
			abort();
		}

		if (ss->fileid != fileid)
			continue; /* not our fileid */

		/* ss->fileid == fileid;
		 * we have found the fileid we're looking for! */
		if (temp_f.first_segments == 0)
			temp_f.first_segments = pageno;

		if (prev_ss)
			prev_ss->next_segments = pageno;

		temp_f.page_alloc++;
		temp_f.cur_segments = pageno;

		prev_ss = ss;
	}

	if (temp_f.page_alloc == 0)
	{
		logmsg_f(LOG_NOTICE, "failed to rebuild fdat for fileid=%lu, "
		    "no sdat data found", fileid);

		/* the only thing we can do is blat the fdat page */
		table_nuke_fileid(d, f, fileid);

		/* we never found a page with our fileid */
		return -1;
	}

	logmsg(LOG_DEBUG, "reconstructing fileid gives: "
	    "page_alloc=%d, first_segments=%d, cur_segments=%d",
	    temp_f.page_alloc, temp_f.first_segments,
	    temp_f.cur_segments);

	memcpy(f, &temp_f, sizeof(struct fileid));
	return 0;

}

int32_t table_backup_eachfile(struct dat_files *d, struct dat_file *f, char *suffix, struct tm *tm)
{
	fd_t fd;
	off_t offset;
	ssize_t bytes_to_go, r, len;
	struct stat sb;
	char newfile[PATH_MAX], tmp[PATH_MAX];
	char *buf;

	basename_r(d->basename, tmp);

	snprintf(newfile, PATH_MAX, "%s/backups/%s.%s.%04d%02d%02d-%02d%02d",
	    g->cfg.dbroot, tmp, suffix,
	    tm->tm_year+1900,tm->tm_mon+1,tm->tm_mday, tm->tm_hour,tm->tm_min);

	if (fstat(f->fd, &sb))
	{
		logmsg_f(LOG_CRIT, "fstat: %s", STR_errno);
		return -1;
	}
	bytes_to_go = sb.st_size;

	len = 128 * 1024; /* 128k read/writes are set here */
	buf = safe_malloc(len);

	if ((fd = open(newfile, O_WRONLY | O_CREAT, (mode_t)0644)) == -1)
	{
		logmsg_f(LOG_CRIT, "open: %s", STR_errno);
		return -1;
	}

	offset = 0;
	while(bytes_to_go)
	{
		r = pread(f->fd, buf, len, offset);
		if (r == -1)
		{
			logmsg_f(LOG_CRIT, "pread: %s", STR_errno);
			close(fd);
			free(buf);
			return -1;
		}

		if (pwrite(fd, buf, r, offset) == -1)
		{
			logmsg_f(LOG_CRIT, "pwrite: %s", STR_errno);
			close(fd);
			free(buf);
			return -1;
		}

		bytes_to_go -= r;
		offset += r;

	}
	close(fd);
	free(buf);

	return 0;
}

int32_t table_backup(struct dat_files *d)
{
	/* given a fully open table in d, create backups of both dat files
	 * into dbroot/backups/basename.sdat.YYYYMMDDHHMM
	*/

	/* no d->opened check, we could be called from
	 * table_open -> table_check and it may still be false */

	struct tm tm;
	time_t now = time(NULL);

	gmtime_r(&now, &tm);

	logmsg_f(LOG_NOTICE, "backing up table %s", d->basename);

	if (table_backup_eachfile(d, &d->s, "sdat", &tm))
		return -1;

	if (table_backup_eachfile(d, &d->f, "fdat", &tm))
		return -1;

	logmsg_f(LOG_NOTICE, "backed up table %s", d->basename);

	return 0;
}

int32_t table_check(struct dat_files *d)
{
	/*
	* Checking/Repairing a table:
	* 1) check every page in the .sdat sequentially:
	* 1a) if magic is wrong, call table_nuke_segments_page
	*    (set everything to zero to indicate unused page)
	*    (we'll deal with the fdat in 2)
	* 1b) if hash is wrong, invoke table_recover_segments_page
	*    (FIXME: does this cope with a new size_used=0?
	*	
	* 2) check every page in the .fdat sequentially:
	* 2a) if magic is wrong, invoke table_repair_rebuild_fileid
	* 2b) ensure the first_segments look sane by checking the
	*    sdat->fileid matches
	* 2c) do the same for the entire chain of ->next_segments
	*    (this is where we find blatted sdat page)
	* 2d) and the same for f->cur_segments
	*
	*    (if any of 2b/c/d are wrong, invoke table_repair_rebuild_fileid)
	*/

	bool backup_done = false;
	uint32_t h;
	fileid_t tf;
	page_off_t i;
	struct fileid   *f;
	struct segments *ss;

	/* no t_lock, we are only ever called from somewhere with the lock */

	/* no d->opened check, we could be called from
	 * table_open and it may still be false */

	logmsg_f(LOG_NOTICE, "checking table %s", d->basename);

	/* 1) sequential sdat check */
	for(i = 1 ; i < d->s.sh->next_free_segment ; i++)
	{
		ss = get_segments_offset_for_page(&d->s, i);

		if (ss->magic == 0 && ss->fileid == 0)
			continue;

		if (ss->magic != SEGMENTS_MAGIC)
		{
			logmsg_f(LOG_CRIT, "ss->magic invalid at offset %p! "
			    "(fileid=%lu(?), magic=%x)",
			    calc_segments_offset(d, ss), ss->fileid, ss->magic);

			/* probably a corrupted page; if the magic
			 * is wrong then we can't guarantee any of
			 * the rest of it is right, so we'll have to
			 * nuke the entire page */

			if (!backup_done)
			{
				table_backup(d); backup_done = true;
			}

			table_nuke_segments_page(d, ss);
		}
		
		if (ss->hash != (h = SEGMENTS_HASH(ss)))
		{
			/* partially corrupted page */
			logmsg_f(LOG_CRIT, "ss->hash invalid at offset %p! "
			    "(fileid=%lu, hash=%x wanted=%x)",
			    calc_segments_offset(d, ss), ss->fileid,
			    ss->hash, h);

			if (!backup_done)
			{
				table_backup(d); backup_done = true;
			}

			table_recover_segments_page(d, ss);
		}

		if (ss->next_segments >= d->s.sh->next_free_segment)
		{
			/* next_segments points to a segments struct that
			 * hasn't been allocated yet. This is wrong! */

			logmsg_f(LOG_CRIT, "ss->next_segments invalid at offset %p! "
			    "(fileid=%lu, next_segments=%lu",
			    calc_segments_offset(d, ss), ss->next_segments);

			if (!backup_done)
			{
				table_backup(d); backup_done = true;
			}

			ss->next_segments = 0;

			/* we should check the chain now.. */
		}
	}

	f = get_files_offset(&d->f);

	/* 2) sequential fdat check */
	for(i = 0 ; i < d->f.fh->files_allocated ; i++, f++)
	{
		if (f->magic == 0 && f->fileid == 0) 
			continue;

		/* work out the fileid that this page *should* be for */
		tf = d->f.fh->fileid_min_req +
		    ((calc_file_offset(d, f) - PAGE_SIZE) /
		    sizeof(struct fileid));

		if (f->fileid != tf)
		{
			/* fileid in the fdat doesn't match what it should
			 * be (calculated from offset) */

			logmsg_f(LOG_ERR, "f->fileid invalid at offset %p! "
			    "(fileid=%lu, but got %lu",
			    calc_file_offset(d, f), tf, f->fileid);

			if (!backup_done)
			{
				table_backup(d); backup_done = true;
			}

			/* skip all subsequent checks;
			 * the fdat is broken and needs repairing */
			table_repair_rebuild_fileid(d, f, tf);
			continue;
		}

		/* 2a check magic in fdat */
		if (f->magic != FILEID_MAGIC)
		{
			/* incorrect magic in the fdat */

			logmsg_f(LOG_ERR, "f->magic invalid at offset %p! "
			    "(fileid=%lu, magic=%x)",
			    calc_file_offset(d, f), tf, f->magic);
			
			if (!backup_done)
			{
				table_backup(d); backup_done = true;
			}

			/* skip all subsequent checks;
			 * the fdat is broken and needs repairing */
			table_repair_rebuild_fileid(d, f, tf);
			continue;
		}


		/* 2b check first_segments looks sane */
		ss = get_first_segments_for_file(d, f);
		if (ss->fileid != f->fileid)
		{
			/* first_segments points at an sdat that isn't ours */

			if (!backup_done)
			{
				table_backup(d); backup_done = true;
			}

			/* skip all subsequent checks;
			 * the fdat is broken and needs repairing */
			table_repair_rebuild_fileid(d, f, tf);
			continue;
		}

		/* 2c now check the chain of next_segments */
		while ((ss = get_next_segments(d->s.m, ss)))
		{
			if (ss == &sentinels.segment_page_out_of_bounds)
			{
				/* this segments page is nonsense; this
				 * usually means the segment points outside
				 * the allocated sdat range */
				abort();
			}

			if (ss->fileid != f->fileid)
			{
				/* ss points at an sdat that isn't ours */

				if (!backup_done)
				{
					table_backup(d); backup_done = true;
				}

				/* skip all subsequent checks;
				 * the fdat is broken and needs repairing */
				table_repair_rebuild_fileid(d, f, tf);
				break;

				/* we should go the next fileid here;
				 * continue won't do it because we're in an
				 * inner loop. break is better but will
				 * still cause 2d to be run. But that's ok */
			}

		} /* get_next_segments() */

		/* 2d check cur_segments in much the same way */
		ss = get_cur_segments_for_file(d, f);
		if (ss->fileid != f->fileid)
		{
			/* cur_segments points at an sdat that isn't ours */

			if (!backup_done)
			{
				table_backup(d); backup_done = true;
			}

			/* skip all subsequent checks;
			 * the fdat is broken and needs repairing */
			table_repair_rebuild_fileid(d, f, tf);
			continue;
		}

	} /* for() */

	/* table has now been verified to be clean */
	d->s.sh->flags &= ~(SDAT_FLAGS_DIRTY);

	logmsg_f(LOG_NOTICE, "table %s marked clean", d->basename);

	return 0;
}

int32_t table_close_no_t_lock(struct dat_files *d)
{
	struct dat_file *s = &d->s;
	struct dat_file *f = &d->f;
	struct stat sb;

	if (!d->opened) return 0;

	d->opened = false; /* not open anymore */

	if (s->fd && s->m)
	{
		if (fstat(s->fd, &sb))
		{
			logmsg_f(LOG_ERR, "fstat (sdat): %s", STR_errno);
			return -1;
		}
		munmap(s->m, sb.st_size);
		s->m = NULL;
	}

	if (s->fd)
	{
		logmsg_f(LOG_NOTICE, "closing %s.sdat [fd=%d]", d->basename, s->fd);
		close(s->fd);
		s->fd = 0;
	}

	if (f->fd && f->m)
	{
		if (fstat(f->fd, &sb))
		{
			logmsg_f(LOG_ERR, "fstat (fdat): %s", STR_errno);
			return -1;
		}
		munmap(f->m, sb.st_size);
		f->m = NULL;
	}

	if (f->fd)
	{
		logmsg_f(LOG_NOTICE, "closing %s.fdat [fd=%d]", d->basename, f->fd);
		close(f->fd);
		f->fd = 0;
	}

#if USE_M_LOCK
	free(f->m_lock);
	f->m_lock = NULL;
#endif

	if (d->basename)
	{
		free(d->basename);
		d->basename = NULL;
	}

	return 0;
}

int32_t table_close(struct dat_files *d)
{
	int32_t e;

	/* we need a write lock; this ensures nothing is using this table
	 * while we close it */
	if (table_lock(d, T_WRLOCK))
	{
		logmsg_f(LOG_ERR, "table_lock error");
		return -1;
	}

	e = table_close_no_t_lock(d);

	table_unlock(d);

	return e;
}

int32_t tables_close_all()
{
	table_count_t i;
	struct dat_files *r;

	tables_sync();

	for(i = 0 ; i < g->t->dats_allocated ; i++)
	{
		r = &g->t->dats[i];

		if (r->opened)
			table_close(r);
	}

	return 0;
}

int32_t tables_close_lru()
{
	/* close the first 5 tables that haven't been looked at for over a
	 * day; this is so we don't run out of space in g->t->open_tables.
	 * 
	 * there is no locking around this - it relies on the fact that we
	 * have more g->t->dats_allocated than we will ever possibly need,
	 * so the oldest ones have rolled off our retention and are now
	 * unreferenced
	*/

	return 0;
}

/* table_open_existing_* functions {{{ */
int32_t table_open_existing_fdat(struct dat_files *d)
{
	uint64_t c;
	struct stat sb;
	char filename[PATH_MAX];
	struct dat_file *f = &d->f;

	snprintf(filename, PATH_MAX, "%s.fdat", d->basename);

	if (stat(filename, &sb))
	{
		/* silent for ENOENT because we're used to test existence */
		if (errno == ENOENT) return E_TABOPEN_EXISTING_ENOENT;

		logmsg_f(LOG_ERR, "stat: %s",STR_errno);
		return -1;
	}

	if (-1 == (f->fd = open(filename, O_RDWR)))
	{
		logmsg_f(LOG_ERR, "open: %s",STR_errno);
		return -1;
	}

	f->m = mmap(NULL, sb.st_size, PROT_RW, MAP_SHARED, f->fd, 0);
	if (f->m == MAP_FAILED)
	{
		logmsg_f(LOG_ERR, "mmap: %s", STR_errno);
		return -1;
	}

	f->fh = (struct fdat_header *)f->m;

	/* sanity check file */
	if (f->fh->file_magic != FDAT_HEADER_MAGIC)
	{
		logmsg_f(LOG_ERR, "%s: didn't find fdat header magic", filename);
		return -1;
	}

	c = (sb.st_size - PAGE_SIZE) / sizeof(struct fileid);
	if (c != f->fh->files_allocated)
	{
		logmsg_f(LOG_ERR,
		    "%s: files_allocated=%d but expecting %d (filesize=%d)",
		    filename, f->fh->files_allocated, c, sb.st_size);
		return -1;
	}

#if USE_M_LOCK
	f->m_lock = safe_calloc(f->fh->files_allocated);
#endif

	f->files = get_files_offset(f);

	logmsg_f(LOG_NOTICE, "%s: opened, used=%d alloc=%d "
	    "min=%d max=%d "
	    "min_req=%d max_req=%d "
	    "version=%d "
	    "[fd=%d]",
	    filename, f->fh->files_used, f->fh->files_allocated,
	    f->fh->fileid_min, f->fh->fileid_max,
	    f->fh->fileid_min_req, f->fh->fileid_max_req,
	    f->fh->file_version,
	    f->fd);

	return 0;
}
int32_t table_open_existing_sdat(struct dat_files *d)
{
	int64_t  r;
	uint64_t c;
	struct stat sb;
	char filename[PATH_MAX];
	struct dat_file *s = &d->s;

	snprintf(filename, PATH_MAX, "%s.sdat", d->basename);

	r = stat(filename, &sb);
	if (r == -1)
	{
		/* silent for ENOENT because we're used to test existence */
		if (errno == ENOENT) return E_TABOPEN_EXISTING_ENOENT;

		logmsg_f(LOG_ERR, "stat: %s",STR_errno);
		return -1;
	}

	if (-1 == (s->fd = open(filename, O_RDWR)))
	{
		logmsg_f(LOG_ERR, "open: %s",STR_errno);
		return -1;
	}

	/* do not include sdat mmaps in a core file */
	s->m = mmap(NULL, sb.st_size, PROT_RW, MAP_SHARED | MAP_NOCORE,s->fd,0);
	if (s->m == MAP_FAILED)
	{
		logmsg_f(LOG_ERR, "mmap: %s", STR_errno);
		return -1;
	}

	s->sh = (struct sdat_header *)s->m;

	/* sanity check file */
	if (s->sh->file_magic != SDAT_HEADER_MAGIC)
	{
		logmsg_f(LOG_ERR, "%s: didn't find sdat header magic", filename);
		return -1;
	}

	c = (sb.st_size - PAGE_SIZE) / PAGE_SIZE;
	if (c != s->sh->segments_allocated)
	{
		logmsg_f(LOG_ERR,
		    "%s: segments_allocated=%d but expecting %d (filesize=%d)",
		    filename, s->sh->segments_allocated, c, sb.st_size);

		/* this means a crash while we were updating the table? */
		if (table_check(d))
		{
			logmsg_f(LOG_ERR, "%s: table_check is unhappy :(",
			   filename);
			return -1;
		}

		/* table_check is happy - update segments_allocated and hope */
		logmsg_f(LOG_WARNING, "%s: table_check is happy, "
		    "forcing segments_allocated to %d", filename, c);
		s->sh->segments_allocated = c;
	}

	logmsg_f(LOG_NOTICE,"%s: opened, "
	    "used=%d alloc=%d "
	    "version=%d flags=%d "
	    "[fd=%d]",
	    filename, s->sh->next_free_segment-1, s->sh->segments_allocated,
	    s->sh->file_version, s->sh->flags, s->fd);

	return 0;
}
int32_t table_open_existing(struct dat_files *d, fileid_t t_min, fileid_t t_max)
{
	int32_t r;
	uint64_t start, dur;
	char b[PATH_MAX];

	if (table_lock(d, T_WRLOCK))
	{
		logmsg_f(LOG_ERR, "table_lock error");
		return -1;
	}

	if (d->opened)
	{
		/* race prevention; someone beat us to it? */
		table_unlock(d);
		return E_TABOPEN_EXISTING_WASOPEN;
	}

	/* ensure we're not running out of space in g->t->dats */
	if (g->t->open_tables == g->t->dats_allocated)
	{
		logmsg_f(LOG_WARNING,
		    "g->t->dats is full, closing a couple of old ones..");
		tables_close_lru();
	}

	/* d->basename may or may not have been allocated already */
	if (d->basename)
		free(d->basename);

	sprintf(b, "%s/MSGID_%d_%d", g->cfg.dbroot, t_min, t_max);

	/* re-set it with our passed filename */
	d->basename = strdup(b); /* freed in table_close() */

	r = table_open_existing_fdat(d);
	if (r < 0)
	{
		table_close_no_t_lock(d); /* we have t_lock already! */
		table_unlock(d);
		return r;
	}

	r = table_open_existing_sdat(d);
	if (r < 0)
	{
		table_close_no_t_lock(d); /* we have t_lock already! */
		table_unlock(d);
		return r;
	}

	if (d->s.sh->flags & SDAT_FLAGS_DIRTY)
	{
		start = get_time_usec();
		table_check(d);
		dur = get_time_usec() - start;
		logmsg_f(LOG_NOTICE,
		    "checking %s took %.3f sec", d->basename, dur/1000000.0);
	}

	d->opened = true;
	d->last_access = get_time_usec();
	table_unlock(d);

	return 0;
}
/* }}} */
/* table_create {{{ */
int32_t table_create(uint64_t slots, struct dat_files *d, fileid_t t_min, fileid_t t_max)
{
	struct dat_file *s = &d->s;
	struct dat_file *f = &d->f;
	char filename[PATH_MAX], b[PATH_MAX];

	if (table_lock(d, T_WRLOCK))
	{
		logmsg_f(LOG_ERR, "table_lock error");
		return -1;
	}

	if (d->opened)
	{
		/* race prevention; someone beat us to it? */
		table_unlock(d);
		return E_TABCREATE_WASOPEN;
	}

	/* ensure we're not running out of space in g->t->dats */
	if (g->t->open_tables == g->t->dats_allocated)
	{
		logmsg_f(LOG_WARNING,
		    "g->t->dats is full, closing a couple of old ones..");
		tables_close_lru();
	}

	/* d->basename may or may not have been allocated already */
	if (d->basename)
		free(d->basename);

	sprintf(b, "%s/MSGID_%d_%d", g->cfg.dbroot, t_min, t_max);

	/* re-set it with our passed filename */
	d->basename = strdup(b); /* freed in table_close() */


	logmsg_f(LOG_DEBUG, "creating %s", d->basename);

	/* open sdat first */
	snprintf(filename, PATH_MAX, "%s.sdat", d->basename);
	if (-1 == (s->fd = open(filename, O_RDWR | O_CREAT, (mode_t)0644)))
	{
		logmsg_f(LOG_ERR, "sdat open: %s", STR_errno);
		table_close(d);
		table_unlock(d);
		return -1;
	}
	if (sdat_resize(slots, s) == -1)
	{
		table_close(d);
		table_unlock(d);
		return -1;
	}

	s->sh->file_magic         = SDAT_HEADER_MAGIC;
	s->sh->file_version       = SDAT_HEADER_CURRENT_VERSION;

	s->sh->flags              = 0;

	s->sh->first_segment      = 1; /* leave 4096 bytes for header */
	s->sh->next_free_segment  = s->sh->first_segment;

	s->sh->segments_allocated = slots;


	/* now the fdat */
	snprintf(filename, PATH_MAX, "%s.fdat", d->basename);
	if (-1 == (f->fd = open(filename, O_RDWR | O_CREAT, (mode_t)0644)))
	{
		logmsg_f(LOG_ERR, "fdat open: %s", STR_errno);
		table_close(d);
		table_unlock(d);
		return -1;
	}
	if (fdat_resize(slots, f) == -1)
	{
		table_close(d);
		table_unlock(d);
		return -1;
	}

	f->fh->file_magic      = FDAT_HEADER_MAGIC;
	f->fh->file_version    = FDAT_HEADER_CURRENT_VERSION;

	f->fh->fileid_min      = UINT_MAX;
	f->fh->fileid_max      = 0;

	f->fh->fileid_min_req = t_min;
	f->fh->fileid_max_req = t_max;

	f->fh->files_used      = 0;

	f->fh->files_allocated = slots;

	/* this is done in fdat_resize */
	//f->files             = get_files_offset(f);

	d->opened = true;
	d->last_access = get_time_usec();
	table_unlock(d);

	return 0;
}
/* }}} */

uint32_t get_pos_for_fileid(const fileid_t fileid)
{
	/* our g->t->dats array is a simple constant-time lookup hash using
	 * the following formula:
	 *
	 * p = (fileid / FILES_PER_FDAT) % MAX_OPEN_TABLES
	 * d = &dats[p]
	*/

	return (fileid / FILES_PER_FDAT) % MAX_OPEN_TABLES;
}

struct dat_files *get_table_for_fileid(const fileid_t fileid, int8_t flags)
{
	int32_t r;
	fileid_t t_min, t_max;
	table_count_t open_at_start;
	struct dat_files *d;
	table_count_t p;

	p = get_pos_for_fileid(fileid);

	if (p > g->t->dats_allocated)
		/* get_pos_for_fileid() returned nonsense */
		return NULL;

	d = &g->t->dats[p];

	open_at_start = g->t->open_tables;

//look_for_table:
	if (d->opened && d->f.fh &&
	    d->f.fh->fileid_min_req <= fileid &&
	    d->f.fh->fileid_max_req >= fileid)
	{
		d->last_access = get_time_usec();
		return d;
	}

#if 0
	/* we do not have an open table for this fileid. this gets tricky
	 * with multiple threads, so we need to lock here. Immediately after
	 * getting the lock, see if another thread has opened a new table;
	 * if it has, we need to do the above check again
	*/
	//pthread_mutex_lock(&g->t->L_open_tables);
	if (open_at_start != g->t->open_tables)
	{
		//pthread_mutex_unlock(&g->t->L_open_tables);
		goto look_for_table;
	}
#endif

	/* we have the lock and nobody else opened the table, so we'll do it */

	/* construct the filename the appropriate table should have */
	t_min = fileid - (fileid % FILES_PER_FDAT);
	t_max = t_min + FILES_PER_FDAT - 1;

	r = table_open_existing(d, t_min, t_max);
	if (r == 0)
	{
		/* table opened */
		atomic_inc_32(g->t->open_tables);
		//pthread_mutex_unlock(&g->t->L_open_tables);
		return d;
	}
	else if (r == E_TABOPEN_EXISTING_WASOPEN)
	{
		/* this is fine, the table was opened while we sat in a lock */
		//pthread_mutex_unlock(&g->t->L_open_tables);
		return d;
	}
	else if (r == E_TABOPEN_EXISTING_ENOENT)
	{
		/* this is fine, the table simply does not exist */
	}
	else
	{
		/* a rather more serious error */
		logmsg_f(LOG_ERR, "got a critical error from table_open_existing");
		//pthread_mutex_unlock(&g->t->L_open_tables);
		return NULL;
	}

	if ((flags & TAB_CREATE) == 0)
	{
		/* we have not been asked to create a table */
		//pthread_mutex_unlock(&g->t->L_open_tables);
		return NULL;
	}

	/* create a new table */
	r = table_create(FILES_PER_FDAT, d, t_min, t_max);
	if (r == E_TABCREATE_WASOPEN)
	{
		/* someone else created the table while we sat in lock */
		//pthread_mutex_unlock(&g->t->L_open_tables);
		return d;
	}
	else if (r < 0)
	{
		/* creation failed */
		//pthread_mutex_unlock(&g->t->L_open_tables);
		return NULL;
	}

	atomic_inc_32(g->t->open_tables);

	//pthread_mutex_unlock(&g->t->L_open_tables);

	return d;
}

struct segment *find_segment(struct segment_local *sl)
{
	uint32_t i, h;
	struct fileid   *f;
	struct segments *ss;
	struct segment  *s;
	struct dat_files *d;
	struct dat_file *fdat, *sdat;

	if ((d = get_table_for_fileid(sl->fileid, TAB_CREATE)) == NULL)
	{
		logmsg_f(LOG_CRIT, "no table for fileid %lu", sl->fileid);
		return NULL;
	}

	fdat = &d->f; sdat = &d->s;

	f = &fdat->files[sl->fileid - fdat->fh->fileid_min_req];
	if (f->fileid != sl->fileid)
	{
		/* the segment cannot exist */
		return NULL;
	}

	if (f->magic != FILEID_MAGIC)
	{
		logmsg_f(LOG_ERR, "f->magic invalid at offset %p! "
		    "(fileid=%lu(?), magic=%x)",
		    calc_file_offset(d, f), f->fileid, f->magic);
		abort();
	}

	ss = get_first_segments_for_file(d, f);

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
			return NULL;
		}

		h = SEGMENTS_HASH(ss);
		if (ss->hash != h)
		{
			logmsg_f(LOG_CRIT, "ss->hash invalid at offset %p! "
			    "(fileid=%lu(?), hash=%x wanted=%x)",
			    calc_segments_offset(d, ss), ss->fileid,
			    ss->hash, h);
			return NULL;
		}

		s = ss->segments;
		for(i = 0 ; i < ss->segment_count ; i++)
		{
			if (s->date    == sl->date &&
			    s->segment == sl->segment &&
			    s->size    == sl->size &&
			    !strncmp(sl->msgid, s->msgid, s->msgid_len))
				return s;

			s = get_next_segment(s);
		}
	} while ((ss = get_next_segments(d->s.m, ss)));

	/* segment not found */
	return NULL;
}
int32_t add_segment(struct segment_local *sl)
{
	uint32_t h;
	uint64_t n;

	struct fileid   *f;
	struct segments *ss;
	struct segment  *s;
	struct dat_file *fdat, *sdat;
	struct dat_files *d;

	/* we need to work out which table to insert into.. this handles
	 * opening/creating the appropriate table as necessary */
	if ((d = get_table_for_fileid(sl->fileid, TAB_CREATE)) == NULL)
	{
		logmsg_f(LOG_CRIT, "no table for fileid %lu", sl->fileid);
		return -1;
	}

	fdat = &d->f; sdat = &d->s;

	/* we need a write lock */
	if (table_lock(d, T_WRLOCK))
	{
		logmsg_f(LOG_ERR, "table_lock error");
		return -1;
	}

	/* look for this fileid already existing in this table */
	f = &fdat->files[sl->fileid - fdat->fh->fileid_min_req];

	if (f->fileid != sl->fileid)
	{
		/* inserts fileid into the struct fileid array in
		 * the correct place */
		f = add_fileid(fdat, sl->fileid);

		/* we're going to need a new segments page for the
		 * first segment of this file so check we have room */
		if (sdat->sh->next_free_segment == sdat->sh->segments_allocated)
		{
			/* add another 1000 pages at a time, this should
			 * avoid having to remap too often */
			n = sdat->sh->segments_allocated + 1000;
			if (-1 == sdat_resize(n, sdat))
			{
				table_unlock(d);
				return -1;
			}
		}

		/* populate f and ss */
		//f->fileid       = fileid;      // done in add_fileid
		f->magic          = FILEID_MAGIC;
		f->first_segments = sdat->sh->next_free_segment++;
		f->cur_segments   = f->first_segments;
		f->page_alloc     = 1; /* have one page of segments */

		ss = get_cur_segments_for_file(d, f);

		ss->next_segments = 0; /* no next yet */
		ss->magic         = SEGMENTS_MAGIC;
		ss->segment_count = 0; /* no segments yet */
		ss->size_used     = 0;
		ss->hash          = 0;
		ss->fileid        = f->fileid;
	}
	else
	{
		if (f->magic != FILEID_MAGIC)
		{
			logmsg_f(LOG_CRIT, "f->magic invalid at offset %p! "
			    "(fileid=%lu(?), magic=%x)",
			    calc_file_offset(d, f), f->fileid, f->magic);
			abort();
		}

		/* the file exists, look up ss */
		ss = get_cur_segments_for_file(d, f);
	}

	if (ss->magic != SEGMENTS_MAGIC)
	{
		/* FIXME: possible data corruption, handle this */

		logmsg_f(LOG_CRIT, "ss->magic invalid at offset %p! "
		    "(fileid=%lu, magic=%x)",
		    calc_segments_offset(d, ss), f->fileid, ss->magic);
		abort(); /* XXX */
	}

	/* before we touch the page, check the old hash still looks valid */
	if (ss->size_used && ss->hash != (h = SEGMENTS_HASH(ss)))
	{
		logmsg_f(LOG_CRIT, "ss->hash invalid at offset %p! "
		    "(fileid=%lu, hash=%x wanted=%x)",
		    calc_segments_offset(d, ss), f->fileid, ss->hash, h);
		abort();
	}


	if (sl->msgid_len == 0) sl->msgid_len = strlen(sl->msgid);

	/* check if ss has enough room for a new segment */
	if (sizeof(struct segments) + ss->size_used +
	    sizeof(struct segment) + sl->msgid_len
	    >= PAGE_SIZE)
	{
		/* no it doesn't; make a new page */

		/* check we're not overrunning our sdat file */
		if (sdat->sh->next_free_segment == sdat->sh->segments_allocated)
		{
			/* add another 1000 pages at a time, this should
			 * avoid having to remap too often */
			n = sdat->sh->segments_allocated + 1000;
			if (-1 == sdat_resize(n, sdat))
			{
				table_unlock(d);
				return -1;
			}

			/* ss may have moved! */
			ss = get_cur_segments_for_file(d, f);
		}

		f->page_alloc++;
		f->cur_segments = sdat->sh->next_free_segment++;
		ss->next_segments = f->cur_segments;

		ss = get_cur_segments_for_file(d, f);
		ss->next_segments = 0;
		ss->magic         = SEGMENTS_MAGIC;
		ss->segment_count = 0;
		ss->size_used     = 0;
		ss->hash          = 0;
		ss->fileid        = f->fileid;
	}

	/* we now have f and ss populated */

#if USE_M_LOCK
	/* place an advisory lock on this page */
	uint32_t *m_lock;
	m_lock = &fdat->m_lock[f->fileid - fdat->fh->fileid_min_req];

	/* if this m_lock is non-zero, something else is updating this
	 * segment.. wait for it */
	while (!atomic_cmpset_int(m_lock, 0, 1))
	{
		logmsg(LOG_DEBUG, "waiting.. (m_lock is %d)", *m_lock);
		sleep(1);
	}
#endif

	/* mark the sdat as 'dirty' meaning this file should be checked if
	 * we crash/when we next open it */
	if (! (sdat->sh->flags & SDAT_FLAGS_DIRTY))
		sdat->sh->flags |= SDAT_FLAGS_DIRTY;

	s = (struct segment *)((char *)ss->segments + ss->size_used);

	s->segment   = sl->segment;
	s->date      = sl->date;
	s->size      = sl->size;
	s->msgid_len = sl->msgid_len;

	memcpy(&s->msgid, sl->msgid, s->msgid_len);

	ss->size_used += sizeof(struct segment) + s->msgid_len;

	ss->segment_count++;

	/* calculate a new MurmurHash CRC */
	ss->hash = SEGMENTS_HASH(ss);

#if USE_M_LOCK
	/* release lock.. */
	atomic_subtract_int(m_lock, 1);
#endif

	table_unlock(d);

	return 0;
}

