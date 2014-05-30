#pragma once

/* LOGFILES: a logfile is named log_%time%.log
 * first 4k is mmap'ed in as struct logfile_header
 * rest of it is appended as struct logfile_entry
*/

#define LOG_COMMIT_NO_FLAGS 0x00
#define LOG_COMMIT_GET_LOCK 0x01

struct logfile_entry
{
	date_t               date;       /* 32; time we received the PUT */

	le_magic_t           magic;      /* 32; magic sanity check       */

	struct segment_local d;         /*2176 bits (272 bytes)          */
} __attribute__ ((packed));
#define LOGFILE_HEADER_CURRENT_VERSION 1
#define LOGFILE_HEADER_FLAG_OPEN 0x01 /* logfile is/was open for writes */
/* unused flags: 0x02 0x04 0x08 0x10 0x20 0x40 0x80 */
struct logfile_header
{
	file_magic_t    file_magic;   /* 64 */

	file_version_t	file_version; /* 16 */
	uint8_t         flags;        /*  8; flags */
	uint8_t         reserved1;    /*  8 .. add something to align */

	log_count_t     row_count;    /* 64; how many rows are in this log  */
	log_count_t     row_applied;  /* 64; how many rows are in db safely */
} __attribute__ ((packed));

/* struct allocated by logfile_commit and passed to be_a_replication_master */
struct logfile_replicate
{
	/* start file/position of these rows */
	char log_file[128];
	off_t log_pos;

	/* and how many rows */
	log_count_t row_count;

	/* be_a_replication_master reads this in rather than logfile_commit
	 * doing it; we don't want to hold up our committing client any
	 * longer than we need to. */
	struct logfile_entry *rows;

	/* array of slaves who should receive these rows */
	struct slave *slvs[MAX_MSGIDDBDS_CONNECTED];
	uint32_t slv_count;

	/* be_a_replication_master initially sets this to slv_count. Each
	 * slave atomically decrements by 1 after processing; if it is zero
	 * we were the last slave to process so we can free this entire
	 * struct */
	uint32_t slv_remaining_count;

	/* take this lock when changing/checking slv_remaining_count */
	pthread_mutex_t LOCKED;
};

/* a client that does a PUT will be assigned a buffer, once it does COMMIT
 * then it's flushed to the current log */
struct logfile_buffer
{
	struct logfile_entry *buf;
	uint64_t used, size;
};

struct logfile 
{
	fd_t fd;
	int32_t mode;
	mmap_t m;
	struct logfile_header *h;

	/* basename is log_${log_open_time}.log */
	char *basename;

	pthread_mutex_t LOCKED; /* whenever something is using the log */
};

int32_t logfile_init_struct(struct logfile **);
int32_t logfile_free_struct(struct logfile **);
int32_t logfile_create(struct logfile *);
int32_t logfile_sync(struct logfile *);
int32_t logfile_close(struct logfile *);
int32_t logfile_open(struct logfile *, char *, uint32_t);
int32_t logfile_open_if_diff(struct logfile *, char *, uint32_t);
int64_t logfile_get_size(struct logfile *);
int64_t logfile_fixup_byte_offset(off_t);
char *logfile_get_current_name(struct logfile *);
off_t logfile_get_current_byte(struct logfile *);
int64_t logfile_seek_to_byte(struct logfile *, off_t);
int32_t logfile_seek_to_row(struct logfile *, log_count_t);
int32_t logfile_read(struct logfile *, struct logfile_entry *, int32_t);
int32_t logfile_add_slave(struct logfile *, struct slave *, char **, ssize_t *);
int32_t logfile_commit(struct logfile *, struct logfile_buffer *, int8_t);
int32_t logfile_move_to_next(struct logfile *);
struct logfile_buffer *logfile_buffer_alloc(int32_t);
int32_t logfile_buffer_free(struct logfile_buffer *);
int32_t logfile_write_row(struct logfile *, struct logfile_buffer *, struct logfile_entry *);
int32_t logfile_replay(struct logfile *);
int32_t logfile_check(char *);
int32_t logfile_check_all(void);
