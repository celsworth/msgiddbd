#pragma once

#define MSGIDDBD_VERSION "0.0.10"

/* it's taken us about 8 years to get to 276000000; hopefully we won't reach
 * a billion for another 20 or more by which time msgiddbd will probably be
 * long out of service.. */
#define MAX_SANE_FILEID 1000000000

/* used for g->masters and g->slaves, thereby setting how many masters and
 * slaves each msgiddbd can talk to */
#define MAX_MSGIDDBDS_CONNECTED 32

#ifndef PAGE_SIZE
# define PAGE_SIZE 4096
#endif

#define STR_errno strerror(errno)

#define SL_SIZE                 32768
#define SOCK_BUFSIZE            32768

#define FILES_PER_FDAT         100000

#define MAX_OPEN_TABLES         50000

#define LOGFILE_BUFFER_SIZE     50000
#define LOGFILE_ROTATE_COUNT  4000000 /* 4000000 rows is just over 1GB */

#define FDAT_HEADER_MAGIC    0x4E5A4246494C4553LL /* NZBFILES */
#define SDAT_HEADER_MAGIC    0x4E5A424D53474944LL /* NZBMSGID */
#define LOGFILE_HEADER_MAGIC 0x4E5A424C4F474844LL /* NZBLOGHD */
#define PERSIST_HEADER_MAGIC 0x4E5A425045525354LL /* NZBPERST */
#define LOGFILE_ENTRY_MAGIC  0x4C4F4752           /* LOGR */
#define SEGMENTS_MAGIC       0x4E                 /* N (for ss->magic) */
#define FILEID_MAGIC         0x415A               /* AZ (for f->magic) */

#define MURMURHASH_SEED      0x4E5A42             /* NZB */

/* error return codes; -1 is always used for general nonrecoverable error */
#define E_TABOPEN_EXISTING_ENOENT  -2
#define E_TABOPEN_EXISTING_WASOPEN -3
#define E_TABCREATE_WASOPEN        -3
#define E_LOGOPEN_WAS_OPEN         -2 /* logfile_open: log was already open */
#define E_LOGMOVE_NO_MORE_LOGS     -2
#define E_LOGBUFFREE_NOT_EMPTY     -2 /* logfile_buffer_free; buf not empty */

#define PROT_RW  (PROT_READ | PROT_WRITE)
#define ONE_YEAR (365 * 24 * 60 * 60)

typedef  int8_t* mmap_t;

typedef uint32_t page_off_t;

typedef uint32_t date_t;          /* BREAKS IN 2039! ohnoez */
typedef uint32_t segment_size_t;
typedef uint16_t segment_no_t;
typedef  uint8_t msgid_len_t;
typedef     char msgid_t;

typedef  uint8_t segment_count_t;
typedef  uint8_t segment_magic_t;

typedef uint32_t fileid_t; 
typedef uint16_t fileid_magic_t;
typedef uint16_t fileid_size_t;
typedef  uint8_t fileid_page_t;

typedef uint64_t file_magic_t;
typedef uint16_t file_version_t;
typedef  uint8_t file_flags_t;

typedef uint32_t table_count_t;

typedef uint64_t log_count_t;
typedef uint64_t log_row_id_t;
typedef  uint8_t log_flags_t;

typedef uint32_t le_magic_t;

typedef  int32_t fd_t;
