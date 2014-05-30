#pragma once

#define SEGMENTS_HASH(ss) MurmurHash2((char *)(ss) + sizeof(struct segments), (ss)->size_used, MURMURHASH_SEED)

#define T_RDLOCK 1 << 0
#define T_WRLOCK 1 << 1

#define TAB_CREATE 1 << 0

struct segment
{
	date_t         date;       /* 32 */
	segment_size_t size;       /* 32 */
	segment_no_t   segment;    /* 16 */

	/* dynamically sized; to find next segment, do:
	 * sizeof(struct segment) + msgid_len
	*/
	msgid_len_t    msgid_len;  /*  8 */
	msgid_t        msgid[];
} __attribute__ ((packed));

/* when we see a new file, allocate 4k for it. This struct goes at the start
 * of that 4k, and the rest is multiple dynamically sized struct segment.
 * When we fill up 4k, get a new block and put a reference in next_segments */
struct segments
{
	uint32_t        hash;          /* 32;CRC check for segments[]        */
	page_off_t      next_segments; /* 32;offset to next page of segments */
	segment_magic_t magic;         /*  8;magic byte, always 0x4e 'N'     */
	segment_count_t segment_count; /*  8;how many segments in this page  */
	fileid_size_t   size_used;     /* 16;bytes used by segments[]        */
	fileid_t        fileid;        /* 32;fileid                          */
	struct segment  segments[];
} __attribute__ ((packed));


struct fileid
{
	fileid_t        fileid;         /* 32 */

	fileid_magic_t  magic;          /* 16;magic bytes; AZ          */
	fileid_page_t   page_alloc;     /*  8;pages allocated for file */
	uint8_t         reserved1;      /*  8;padding */

	/* offset [in pages] to first page of segments for this fileid */
	page_off_t      first_segments; /* 32 */
	page_off_t      cur_segments;   /* 32 */
} __attribute__ ((packed));

/* header that goes at the start of every .fdat file */
#define FDAT_HEADER_CURRENT_VERSION 1
struct fdat_header
{
	file_magic_t	file_magic;      /* 64 */

	file_version_t	file_version;    /* 16 */
	uint16_t        reserved1;       /* 16 .. add something to align */

	fileid_t	fileid_min;      /* 32 */
	fileid_t	fileid_max;      /* 32 */

	fileid_t	fileid_min_req;  /* 32 */
	fileid_t	fileid_max_req;  /* 32 */

	page_off_t      files_used;      /* 32 */
	page_off_t      files_allocated; /* 32 */
} __attribute__ ((packed));

/* header that goes at the start of every .sdat file */
#define SDAT_HEADER_CURRENT_VERSION 1

/* unused flags: 0x02 0x04 0x08 0x10 0x20 0x40 0x80 */
#define SDAT_FLAGS_DIRTY            0x01 /* we've written to this file */
struct sdat_header
{
	file_magic_t    file_magic;         /* 64 */

	file_version_t	file_version;       /* 16 */
	file_flags_t    flags;              /*  8 */
	int8_t          reserved1;          /* 8 bits of alignment */

	page_off_t	first_segment;      /* 32; not really used.. */
	page_off_t	next_free_segment;  /* 32 */

	page_off_t      segments_allocated; /* 32 */
} __attribute__ ((packed));


/* a neat tidy place to keep everything associated with a dat file */
struct dat_file
{
	fd_t fd;
	mmap_t m;
	union
	{
		struct fdat_header *fh;
		struct sdat_header *sh;
	};

#if USE_M_LOCK
	// mmap lock, for either per-fileid or per-segments lock
	uint32_t *m_lock;
#endif

	union
	{
		struct fileid *files;
		//struct segments *segments; // not needed yet
	};
};

/* one of these represents an open table */
struct dat_files
{
	char *basename;
	struct dat_file f, s;

	/* table lock - if contention gets bad, we'll rethink this */
	pthread_rwlock_t t_lock;

	uint64_t last_access; /* for closing LRU */
	uint8_t opened;
};

struct tables
{
	pthread_mutex_t L_open_tables;
	table_count_t open_tables;

	table_count_t dats_allocated;

	struct dat_files *dats; /* array of open dats */
};

/* for returning arbitrary errors from functions that need to return a
 * pointer. Just compare the returned value to sentinels.foo */
struct
{
	/* get_first_segments_for_file / get_cur_segments_for_file */
	struct segments segment_page_out_of_bounds;

} sentinels;


ssize_t filesize(fd_t);
uint32_t MurmurHash2(const void *, uint32_t, uint32_t);
uint64_t calc_file_offset(struct dat_files *, struct fileid *);
uint64_t calc_segments_offset(struct dat_files *, struct segments *);
inline struct fileid *get_files_offset(struct dat_file *);
inline struct segments *get_segments_offset(struct dat_file *);
inline struct segments *get_first_segments_for_file(struct dat_files *, struct fileid *);
inline struct segments *get_cur_segments_for_file(struct dat_files *, struct fileid *);
inline struct segments *get_next_segments(mmap_t, struct segments *);
inline struct segment *get_next_segment(struct segment *);
struct fileid *add_fileid(struct dat_file *, const fileid_t);
int32_t table_lock_init(struct dat_files *);
int32_t table_lock_free(struct dat_files *);
int32_t table_lock(struct dat_files *, int8_t);
int32_t table_unlock(struct dat_files *);
int32_t tables_sync(void);
int32_t resize_mmaped_file(uint64_t, struct dat_file *);
int32_t fdat_resize(uint64_t, struct dat_file *);
int32_t sdat_resize(uint64_t, struct dat_file *);
int32_t table_nuke_segments_page(struct dat_files *, struct segments *);
int32_t table_recover_segments_page(struct dat_files *, struct segments *);
int32_t table_repair_rebuild_fileid(struct dat_files *, struct fileid *, fileid_t);
int32_t table_backup(struct dat_files *);
int32_t table_check(struct dat_files *);
int32_t table_close_no_t_lock(struct dat_files *);
int32_t table_close(struct dat_files *);
int32_t tables_close_all(void);
int32_t tables_close_lru(void);
int32_t table_open_existing_fdat(struct dat_files *);
int32_t table_open_existing_sdat(struct dat_files *);
int32_t table_open_existing(struct dat_files *, fileid_t, fileid_t);
int32_t table_create(uint64_t, struct dat_files *, fileid_t, fileid_t);
uint32_t get_pos_for_fileid(const fileid_t);
struct dat_files *get_table_for_fileid(const fileid_t, int8_t);
struct segment *find_segment(struct segment_local *);
int32_t add_segment(struct segment_local *);
