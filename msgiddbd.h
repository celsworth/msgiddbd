#pragma once

/* for logfiles */
struct segment_local /* 272 bytes per struct */
{
	fileid_t       fileid;     /* 32 */
	date_t         date;       /* 32 */
	segment_size_t size;       /* 32 */
	segment_no_t   segment;    /* 16 */
	msgid_len_t    msgid_len;  /*  8 */
	int8_t         reserved;   /*  8 alignment bits */
	msgid_t        msgid[256];
} __attribute__ ((packed));
/* temporary local storage for sorting before send */
struct segment_local_p /* as above, but a pointer for msgid */
{
	fileid_t       fileid;     /* 32 */
	date_t         date;       /* 32 */
	segment_size_t size;       /* 32 */
	segment_no_t   segment;    /* 16 */
	msgid_len_t    msgid_len;  /*  8 */
	msgid_t        *msgid_p;   /*  8 */
};

/* persistent data that we need to remember across restarts */
/* this is stored in file DATABASE_PERSISTENT_DATA (pd.dat) */
/* we pad it to 4k so more can be added and it should carry on working */
/* also note it's completely unused atm ;) - left code in for future re-use */
struct persistent_data_header
{
	file_magic_t    magic;         /* 64 */
} __attribute__ ((packed));

struct persistent_data
{
	fd_t fd;
	mmap_t m;
	struct persistent_data_header *h;
} __attribute__ ((packed));

/* keep track of which msgiddbds we are connected to; this is allocated to
 * MAX_MSGIDDBDS_CONNECTED and used in a 1:1 mapping between
 * cfg->remotes:serverX as g->masters[X] */
struct master
{
	pthread_t thread;
	bool thread_running;

	char id[128];

	/* fd=0 signifies not connected */
	fd_t fd;
	FILE *stream;

	/* keep track of our master's logfile/position */
	char log_file[128];
	ssize_t log_pos;

	/* from masters.ini; is this master actually turned on? */
	bool enabled;

	/* keep count of the number of rows we've done since connecting to
	 * this master */
	uint64_t segments_replicated;
};

/* we use an array of these to keep track of other msgiddbd's connected to us */
struct slave
{
	/* use zero here to indicate unconnected member */
	fd_t fd;

	/* server identification (local:id cfg value) - these should be
	 * unique amongst the array; ie only one connection to a server  */
	char id[128];

	bool in_live_replication;

	bool stop_replicating; /* be_a_slave_cmd_reader sets this on 'STOP' */

	struct Queue *incoming_rows;

	/* where is the slave in replication? */
	char log_file[128];
	ssize_t log_pos;

};

/* global struct to dump everything that needs accessing everywhere */
struct ShareData
{
	uint8_t inserts_enabled;

	time_t time_start;

	uint32_t open_clients;
	uint64_t total_clients;

	uint64_t last_stat_time;

	uint64_t segments_inserted, segments_selected;

	/* number of segments read/executed from all masters since start */
	uint64_t segments_replicated;

	//dictionary *cfg;
	struct
	{
		/* these are all just pointers unless otherwise noted */
		char *file;
		char *local_id;

		char *dbroot;

		char *port;
		char *stats_port;
	} cfg;

	struct Queue *threads_to_reap;

	struct Queue *replicated_log_entries;

	struct Queue *incoming_clients;
	uint32_t client_handler_count;

	struct tables *t;

	struct logfile *l; /* the current logfile being written to */
	pthread_mutex_t L_logfile_rotation;

	struct persistent_data *pd;

	/* allocated to MAX_MSGIDDBDS_CONNECTED */
	struct slave *slaves;
	struct master *masters;

	int32_t signal;
	bool time_to_die;
};


/* global anonymous struct so that the signal handler can see threads */
struct
{
	pthread_t listener, sighandler, replication_master,
	    reaper, stats_listen;
} threads;
