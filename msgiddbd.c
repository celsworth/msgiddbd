/* msgidDBd - a database to store Message-IDs
**
*/

/* send network traffic (excluding msgid lists) to LOG_DEBUG */
#define DEBUG_LOG_TRAFFIC 0

/* function return code standard:
** -2 and below: specific error, use a #define
** -1: general error
**  0: general success
** >0: specific success, ie returning number of bytes processed/read/written
** functions that return a malloc'ed/looked up pointer return NULL on failure
*/
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

#include "prototypes.h"

#include "iniparser3.0b/src/iniparser.h"

struct ShareData *g; /* global shared data */
int8_t cfg_foreground = 1;

void sigusr1_handler(int s) { (void)s; }


/* pd_* {{{ */
int32_t pd_open(struct persistent_data *pd)
{
	int32_t r;
	uint8_t creating = 0;
	struct stat sb;
	char filename[PATH_MAX];

	sprintf(filename, "%s/pd.dat", g->cfg.dbroot);

	/* ENOENT isn't an error, we'll just make one */
	r = stat(filename, &sb);
	if (r == -1)
	{
		if (errno != ENOENT)
		{
			logmsg_f(LOG_ERR, "stat: %s", STR_errno);
			return -1;
		}

		creating = 1;
	}
	else
	{
		/* the file exists, check that it looks the right size */
		if (sb.st_size != PAGE_SIZE)
		{
			logmsg_f(LOG_ERR, "%s: is not %d bytes (is %d)",
			    filename, PAGE_SIZE, sb.st_size);
			logmsg_f(LOG_ERR, "%s: considering invalid", filename);
			return -1;
		}
	}

	/* open DATABASE_PERSISTENT_DATA */
	pd->fd = open(filename,
	    O_RDWR | O_CREAT | O_EXLOCK | O_NONBLOCK, (mode_t)0644);
	if (pd->fd == -1)
	{
		logmsg_f(LOG_ERR, "open: %s", STR_errno);
		return -1;
	}

	if (creating)
	{
		logmsg_f(LOG_NOTICE, "%s: creating new file", filename);
		r = ftruncate(pd->fd, PAGE_SIZE);
		if (r == -1)
		{
			logmsg_f(LOG_ERR, "truncate: %s", STR_errno);
			return -1;
		}
	}

	pd->m = mmap(NULL, PAGE_SIZE, PROT_RW, MAP_SHARED, pd->fd, 0);
	pd->h = (struct persistent_data_header *)pd->m;

	if (creating)
	{
		pd->h->magic         = PERSIST_HEADER_MAGIC;
	}

	if (pd->h->magic != PERSIST_HEADER_MAGIC)
	{
		close(pd->fd);
		logmsg_f(LOG_ERR, "%s: didn't find header magic", filename);
		return -1;
	}

	logmsg_f(LOG_NOTICE, "%s: opened ok", filename);

	return 0;
}
int32_t pd_sync(struct persistent_data *pd)
{
	return fsync(pd->fd);
}
int32_t pd_close(struct persistent_data *pd)
{
	munmap(pd->m, PAGE_SIZE);
	pd_sync(pd);
	close(pd->fd);
	return 0;
}
/* }}} */

int32_t slave_connect(struct master *m, char *host, char *port)
{
	int32_t e;
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((e = getaddrinfo(host, port, &hints, &res)))
	{
		logmsg_f(LOG_CRIT, "getaddrinfo: %s", gai_strerror(e));
		return -1;
	}

	if ((m->fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1)
	{
		logmsg_f(LOG_CRIT, "socket: %s", STR_errno);
		freeaddrinfo(res);
		return -1;
	}

	if (connect(m->fd, res->ai_addr, res->ai_addrlen))
	{
		logmsg_f(LOG_CRIT, "connect(%s): %s", m->id, STR_errno);
		freeaddrinfo(res);
		return -1;
	}

	/* once connected, res is no longer needed */
	freeaddrinfo(res);

	return 0;
}

int32_t slave_check_response(struct master *m, char *check, char *buf)
{
	if (!fgets(buf, SOCK_BUFSIZE, m->stream))
	{
		if (feof(m->stream))
			logmsg_f(LOG_CRIT, "master=%s closed connection",m->id);
		else
			logmsg_f(LOG_CRIT, "master=%s: fgets: error %d",
			    m->id, ferror(m->stream));

		return -1;
	}
	if (strncmp(buf, check, strlen(check)))
	{
		logmsg_f(LOG_ERR, "master=%s: wanted:%s ; got:%s",
		    m->id, check, buf);
		return -1;
	}
	return 0;
}

int32_t slave_send_stopquit(struct master *m)
{
	/* send STOP and QUIT to a replication master, handling the returns */
	char buf[SOCK_BUFSIZE];

	sockwrite(m->fd, "STOP");
	if (slave_check_response(m, "200", buf))
		return -1;

	sockwrite(m->fd, "QUIT");
	if (slave_check_response(m, "299", buf))
		return -1;

	return 0;
}

void *be_a_replication_slave(void *arg)
{
	/* connect to another msgiddbd, identify ourselves as a slave at the
	 * appropriate logfile/position, and process rows from them */

	/* masters.ini is used for "initial seeding" of a master.
	 * iniparser reads this initially, then creates /db/dev1.rbsov_15002.dat
	 * (or whatever the master is called) for an up to date version of
	 * the file/pos which can then be removed from masters.ini
	 *
	 * [dev1.rbsov_15002]
	 * host=
	 * port=
	 * enabled=0/1
	 * file=log_1269429653.log
	 * pos=621923296
	*/

	fd_t master_dat_fd;
	int32_t r;
	dictionary *cfg;
	char *host, *port;
	char tchar[256];
	char buf[SOCK_BUFSIZE];
	struct segment_local sl;
	struct master *m = arg;

	logmsg_f(LOG_NOTICE, "starting up (master=%s)", m->id);

	m->thread_running = true;
	m->segments_replicated = 0;

	/* borrow buf for the masters.ini full path/filename */
	snprintf(buf, PATH_MAX, "%s/masters.ini", g->cfg.dbroot);
	if ((cfg = iniparser_load(buf)) == NULL)
	{
		logmsg_f(LOG_CRIT, "can't open %s - no replication possible!", buf);
		return NULL;
	}

	/* borrow it again to open master datfile if it exists,
	 * to get most recent file/pos */
	snprintf(buf, PATH_MAX, "%s/%s.dat", g->cfg.dbroot, m->id);
	if ((master_dat_fd = open(buf, O_RDWR)) > 0)
	{
		/* read last file/position */
		if ((r = read(master_dat_fd, buf, SOCK_BUFSIZE)) == -1)
		{
			logmsg_f(LOG_CRIT, "read master_dat: %s", STR_errno);
			iniparser_freedict(cfg);
			return NULL;
		}
		buf[r] = 0x0;	

		/* split buf into file/pos the lazy way */
		r = sscanf(buf, "%s %zd", m->log_file, &m->log_pos);
		if (r != 2)
		{
			logmsg_f(LOG_CRIT, "master=%s: corrupted .dat?", m->id);
			iniparser_freedict(cfg);
			return NULL;
		}
	}
	else
	{
		/* it didn't exist; create it (buf is still /db/foo.dat */
		master_dat_fd = open(buf, O_RDWR | O_CREAT, (mode_t)0600);

		/* we'll seed file/pos from the ini */
		char *file, *pos, file_id[256], pos_id[256];

		snprintf(file_id, 256, "%s:file", m->id);
		snprintf(pos_id,  256, "%s:pos",  m->id);
		file = iniparser_getstring(cfg, file_id, NULL);
		pos  = iniparser_getstring(cfg, pos_id, NULL);
		if (!file || !pos)
		{
			logmsg_f(LOG_ERR,
			    "file/position not found in masters.ini for %s",
			    m->id);
			iniparser_freedict(cfg);
			close(master_dat_fd);
			return NULL;
		}

		strcpy(m->log_file, file);
		m->log_pos = atol(pos);

		/* seed the .dat with our first position */
		r = sprintf(buf, "%s %zd", m->log_file, m->log_pos);
		buf[r] = 0x0;
		pwrite(master_dat_fd, buf, r+1, 0);
	}

	snprintf(tchar, 256, "%s:host", m->id);
	host = iniparser_getstring(cfg, tchar, NULL);
	snprintf(tchar, 256, "%s:port", m->id);
	port = iniparser_getstring(cfg, tchar, NULL);

	snprintf(tchar, 256, "%s:enabled", m->id);
	m->enabled = iniparser_getboolean(cfg, tchar, false);

	if (m->enabled == false)
	{
		logmsg_f(LOG_NOTICE, "master=%s: enabled=false", m->id);
		iniparser_freedict(cfg);
		close(master_dat_fd);
		return NULL;
	}


	logmsg_f(LOG_NOTICE, "connecting (master=%s, pos=%s:%zd)",
	    m->id, m->log_file, m->log_pos);

	if (slave_connect(m, host, port) == -1)
	{
		logmsg_f(LOG_CRIT, "master=%s: slave_connect failed", m->id);
		iniparser_freedict(cfg);
		close(master_dat_fd);
		return NULL;
	}

	/* we're connected, start talking */

	/* fdopen a FILE descriptor to make it easy to read a line at a time */
	m->stream = fdopen(m->fd, "r");

	/* make sure we have a 200 welcoming banner */
	if (slave_check_response(m, "200", buf))
	{
		iniparser_freedict(cfg);
		close(master_dat_fd);
		return NULL;
	}

	/* identify ourselves and our log/position.. */
	sprintf(buf, "SLAVE %s %s %zd",g->cfg.local_id,m->log_file,m->log_pos);
	sockwrite(m->fd, buf);
	if (slave_check_response(m, "210", buf))
		goto bail;

	logmsg_f(LOG_NOTICE, "replicating (master=%s, pos=%s:%zd)",
	    m->id, m->log_file, m->log_pos);

	/* start reading rows \o/ */
	char *p, *space;
	while((p = fgets(buf, SOCK_BUFSIZE, m->stream)))
	{
		if (g->time_to_die)
			break;

		if ((p = strchr(buf, '\n'))) *p = 0x0;
		if ((p = strchr(buf, '\r'))) *p = 0x0;

		/* buf should be of the form
		 * log_X.log:pos fileid:seg:date:size:msgid
		*/
		p = strchr(buf, ' '); /* between pos and fileid */
		if (!p)
		{
			/* malformed line? */
			logmsg_f(LOG_ERR, "master=%s sent malformed line (%s)", m->id, buf);
			continue;
		}
		*p = '\0'; /* null that space */
		space = p+1;

		/* split log and pos */
		p = strchr(buf, ':');
		if (!p)
		{
			logmsg_f(LOG_ERR, "master=%s sent malformed log part (%s)", m->id, buf);
			continue;
		}
		*p = '\0'; /* null the : */
		p++;


		if (split_put(space, &sl) == -1)
		{
			/* some error parsing the PUT part */
			logmsg_f(LOG_ERR, "master=%s sent malformed PUT part (%s)", m->id, space);
			continue;
		}

		if (add_segment(&sl))
		{
			logmsg_f(LOG_ERR, "master=%s: error inserting segment (%s)", m->id, space);
			break;
		}

		m->segments_replicated++;
		atomic_inc_64(g->segments_replicated);

		/* update our local position */
		strcpy(m->log_file, buf);
		m->log_pos = atol(p);

		/* and update position to reflect we have just done this row */
		m->log_pos += sizeof(struct logfile_entry);

		r = sprintf(buf, "%s %zd", m->log_file, m->log_pos);
		buf[r] = 0x0;
		pwrite(master_dat_fd, buf, r+1, 0);
	}

	if (!p)
	{
		logmsg_f(LOG_ERR, "master=%s: fgets error?", m->id);
	}

	/* stop replication gracefully */
	if (slave_send_stopquit(m) == -1)
	{
		logmsg_f(LOG_CRIT, "master=%s: stop/quit error", m->id);
	}

bail:
	logmsg_f(LOG_NOTICE, "shutting down (master=%s, pos=%s:%zd)",
	    m->id, m->log_file, m->log_pos);
	fclose(m->stream); m->stream = NULL;
	close(m->fd); m->fd = 0;
	close(master_dat_fd);

	m->thread_running = false;

	return NULL;
}


void *be_a_replication_master(void *arg)
{
	/* sit and watch g->replicated_log_entries. This will be a stream of
	 * struct logfile_replicate pointers.
	 *
	 * This thread is responsible for freeing the logfile_replicate
	 * pointers after they are no longer needed
	*/

	(void)arg;
	uint32_t i;
	struct logfile_replicate *p;
	struct logfile *l;

	logmsg_f(LOG_NOTICE, "starting up");

	logfile_init_struct(&l);

	while((p = queue_deq(g->replicated_log_entries)))
	{
		p->slv_remaining_count = p->slv_count;

		pthread_mutex_init(&p->LOCKED, NULL);

		/* open the log if we need to; we could use an efficient way
		 * to compare p->log_file with our l->basename; see next
		 * note however, we only need to do this comparison once per
		 * batch*/
		logfile_open_if_diff(l, p->log_file, O_RDONLY);

		/* allocate space for rows */
		p->rows= safe_malloc(sizeof(struct logfile_entry)*p->row_count);

		/* read in the rows. logfile_commit guarantees that a batch
		 * of replicated entries that are passed to us will always
		 * be in the same log (they're done in a single write()) so
		 * we can do this in a single logfile_read */
		logfile_seek_to_byte(l, p->log_pos);
		logfile_read(l, p->rows, p->row_count);

		/* for each slave connected with slv->in_live_replication
		 * set, give them this information */
		for(i = 0 ; i < p->slv_count ; i++)
			queue_enq(p->slvs[i]->incoming_rows, p);
	}

	logfile_close(l);
	logfile_free_struct(&l);

	logmsg_f(LOG_NOTICE, "shutting down");
	return NULL;
}

void *be_a_stats_listener(void *arg)
{
	/* listening thread for stats; this is mostly for RRD/nagios to
	 * simplify getting stats out; we split back our statistics
	 * immediately on open then immediately close the connection,
	 * requiring no input from the client (like the normal port does) */

	(void)arg;

	int32_t yes = 1;
	int32_t e, s, c;
	struct client t;
	struct addrinfo hints, *res;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if ((e = getaddrinfo(NULL, g->cfg.stats_port, &hints, &res)))
	{
		logmsg_f(LOG_ERR, "getaddrinfo: %s", gai_strerror(e));
		exit(1); /* XXX */
	}

	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s < 0)
	{
		logmsg_f(LOG_ERR, "socket: %s", STR_errno);
		exit(1);
	}

	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

	if (bind(s, res->ai_addr, res->ai_addrlen) < 0)
	{
		close(s);
		logmsg_f(LOG_ERR, "bind: %s", STR_errno);
		exit(1);
	}

	if ((-1 == listen(s, 5)))
	{
		close(s);
		logmsg_f(LOG_ERR, "listen: %s", STR_errno);
		exit(1);
	}

	logmsg_f(LOG_NOTICE, "listening for stat requests on port %s",
	    g->cfg.stats_port);

	while(g->time_to_die == false)
	{
		c = accept(s, NULL, 0);
		if (c == -1)
		{
			logmsg_f(LOG_ERR, "accept: %s", STR_errno);
			continue;
		}

		/* abusing a client struct a bit just so I didn't have
		 * to rewrite client_do_stats which expects that struct */
		t.client_fd = c;
		client_do_stats(&t, NULL);
		close(c);
	}

	logmsg_f(LOG_NOTICE, "shutting down");

	freeaddrinfo(res);

	return NULL;
}
 
void *be_a_listener(void *arg)
{
	/* listening thread; accept connections over TCP and process
	 * requests from the client, which could be any of:
	 *  PHP asking for NZBs
	 *  Perl giving us new Message-IDs
	 *  another msgiddbd wanting updates that we get from Perl
	*/
	(void)arg;

	int one = 1;
	int32_t yes = 1;
	int32_t e, s, fd;
	struct client *c;
	struct child_info *t;
	struct addrinfo hints, *res;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if ((e = getaddrinfo(NULL, g->cfg.port, &hints, &res)))
	{
		logmsg_f(LOG_ERR, "getaddrinfo: %s", gai_strerror(e));
		exit(1); /* XXX */
	}

	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s < 0)
	{
		logmsg_f(LOG_ERR, "socket: %s", STR_errno);
		exit(1);
	}

	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

	if (bind(s, res->ai_addr, res->ai_addrlen) < 0)
	{
		close(s);
		logmsg_f(LOG_ERR, "bind: %s", STR_errno);
		exit(1);
	}

	if ((-1 == listen(s, 5)))
	{
		close(s);
		logmsg_f(LOG_ERR, "listen: %s", STR_errno);
		exit(1);
	}

	logmsg_f(LOG_NOTICE,"listening for connections on port %s",g->cfg.port);
	while(g->time_to_die == false)
	{
		fd = accept(s, NULL, 0);
		if (fd == -1)
		{
			logmsg_f(LOG_ERR, "accept: %s", STR_errno);
			continue;
		}

		if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(int)))
		{
			logmsg_f(LOG_ERR, "setsockopt: %s", STR_errno);
			continue;
		}

		c = safe_calloc(sizeof(struct client));
		c->client_fd = fd;

		/* check if we're running out of client_handlers..
		 * this is not atomic, so a thread might decrease it while
		 * we're doing this, but that's not critical, we'll just end
		 * up with a spare thread or two */
		if (g->open_clients == g->client_handler_count)
		{
			t = safe_calloc(sizeof(struct child_info));
			pthread_create(&t->thread, NULL, be_a_client_handler,t);
		}
		/* if we have 10 more handlers than clients, shut one down */
		else if (g->client_handler_count > g->open_clients + 10)
		{
			queue_enq(g->incoming_clients, NULL);
		}

		/* hand over the client to a waiting client_handler */
		queue_enq(g->incoming_clients, c);

		atomic_inc_32(g->open_clients);
		g->total_clients++;
	}

	logmsg_f(LOG_NOTICE, "shutting down");
	freeaddrinfo(res);
	return NULL;
}

void *be_a_thread_reaper(void *arg)
{
	/* watch g->threads_to_reap and pthread_join them so we don't end up
	 * with millions of zombie threads */

	int32_t e;
	(void)arg;
	struct child_info *c;

	logmsg_f(LOG_NOTICE, "starting up");

	while ((c = queue_deq(g->threads_to_reap)))
	{
		if ((e = pthread_join(c->thread, NULL)))
			logmsg_f(LOG_ERR, "pthread_join: %s", strerror(e));

		free(c);
	}

	logmsg_f(LOG_NOTICE, "shutting down");

	return NULL;
}

void *be_a_signal_handler(void *arg)
{
	int32_t rc, sig_caught;
	sigset_t *sigmask = arg;

	rc = sigwait (sigmask, &sig_caught);
	switch (sig_caught)
	{
		case SIGINT:
		case SIGTERM:
			g->time_to_die = true;

			/* we have to interrupt some threads ourself */
			pthread_kill(threads.listener, SIGUSR1);

			break;
	}

	//logmsg(LOG_CRIT, "Caught signal: %d", sig_caught);
	g->signal = sig_caught;

	return NULL;
}

int32_t replication_connect_masters()
{
	/* spawn a thread for each master we have defined */
	uint32_t serverno;
	struct master *m;

	for(serverno = 1 ; serverno < MAX_MSGIDDBDS_CONNECTED ; serverno++)
	{
		m = &g->masters[serverno];

		if (m->id[0])
			pthread_create(&m->thread,
			    NULL, be_a_replication_slave, m);
	}

	return 0;
}

void usage(void)
{
	fprintf(stderr,
	"msgiddbd v%s, built at %s\n"
	"\n"
	"Usage:\n"
	"  -c cfgfile\tconfiguration file to read [config.ini]\n"
	"\n",
	MSGIDDBD_VERSION, __TIMESTAMP__
	);
}

void parse_cmdline(int32_t argc, char *argv[])
{
	int32_t ch;

	while ((ch = getopt(argc, argv, "hc:")) != -1)
	{
		switch (ch)
		{
			case 'c': /* configuration file */
			g->cfg.file = strdup(optarg);
			break;

			case 'h':
			default: usage(); exit(0);
		}
	}
}

void read_cfg(char *cfg_file)
{
	uint32_t serverno;
	char *t, string[128];
	struct stat sb;
	struct statfs stats;
	dictionary *dict;
	struct master *m;

	if (stat(cfg_file, &sb))
	{
		logmsg_f(LOG_CRIT, "stat failed on %s", cfg_file);
		exit(1);
	}

	dict = iniparser_load(cfg_file);
	if (! dict)
	{
		logmsg_f(LOG_CRIT, "can't load config file %s", cfg_file);
		exit(1);
	}

	/* rather than repeatedly call iniparser_getstring for some of the
	 * more commonly-accessed values, we'll do it once now and set up
	 * some pointers. We don't change the file or support re-reading it
	 * yet so these shouldn't be invalidated */
	g->cfg.local_id = iniparser_getstring(dict, "local:id", NULL);
	if (! g->cfg.local_id)
	{
		logmsg_f(LOG_ERR, "local:id not found or invalid!");
		exit(1);
	}

	g->cfg.dbroot = safe_malloc(PATH_MAX);
	t = iniparser_getstring(dict, "local:dbroot", NULL);
	if (!t)
	{
		logmsg_f(LOG_ERR, "local:dbroot not in config?");
		exit(1);
	}
	if (stat(t, &sb))
	{
		logmsg_f(LOG_CRIT, "stat: dbroot: %s", STR_errno);
		exit(1);
	}
	if (! realpath(t, g->cfg.dbroot))
	{
		logmsg_f(LOG_ERR, "paths:root not found or invalid!");
		exit(1);
	}

	if (statfs(g->cfg.dbroot, &stats) == -1)
	{
		logmsg_f(LOG_ERR, "statfs: %s", STR_errno);
		exit(1);
	}
	if (100.0 * stats.f_bfree/stats.f_blocks < 1)
	{
		logmsg_f(LOG_CRIT, "refusing to start with a full dbroot");
		exit(1);
	}

#if 0
	g->cfg.local_logdir = safe_malloc(PATH_MAX);
	t = iniparser_getstring(dict, "local:logdir", NULL);
	if (t && stat(t, &sb))
	{
		logmsg_f(LOG_CRIT, "stat: logdir: %s", STR_errno);
		exit(1);
	}
	if (! t || ! realpath(t, g->cfg.local_logdir))
	{
		/* logdir not specified; this isn't an error, use dbroot */
		free(g->cfg.local_logdir);
		g->cfg.local_logdir = strdup(g->cfg.local_dbroot);
	}
	g->cfg.local_logdir_len = strlen(g->cfg.local_logdir);

	g->cfg.local_bakdir = safe_malloc(PATH_MAX);
	t = iniparser_getstring(dict, "local:bakdir", NULL);
	if (t && stat(t, &sb))
	{
		logmsg_f(LOG_CRIT, "stat: bakdir: %s", STR_errno);
		exit(1);
	}
	if (! t || ! realpath(t, g->cfg.local_bakdir))
	{
		/* bakdir not specified; this isn't an error, use dbroot */
		free(g->cfg.local_bakdir);
		g->cfg.local_bakdir = strdup(g->cfg.local_dbroot);
	}
	g->cfg.local_bakdir_len = strlen(g->cfg.local_bakdir);


	if (statfs(g->cfg.local_logdir, &stats) == -1)
	{
		logmsg_f(LOG_ERR, "statfs: %s", STR_errno);
		exit(1);
	}
	if (100.0 * stats.f_bfree/stats.f_blocks < 1)
	{
		logmsg_f(LOG_CRIT, "refusing to start with a full logdir");
		exit(1);
	}
#endif

	g->cfg.port = iniparser_getstring(dict, "local:port", "0");
	if (g->cfg.port[0] == '0')
	{
		logmsg_f(LOG_CRIT, "local:port error");
		exit(1);
	}

	g->cfg.stats_port = iniparser_getstring(dict, "local:stats_port", "0");
	if (g->cfg.stats_port[0] == '0')
	{
		logmsg_f(LOG_CRIT, "local:stats_port error");
		exit(1);
	}

	/* initialise g->masters */
	for(serverno = 1 ; serverno < MAX_MSGIDDBDS_CONNECTED ; serverno++)
	{
		m = &g->masters[serverno];
		m->thread_running = false;

		sprintf(string, "remotes:server%u", serverno);
		if (!(t = iniparser_getstring(dict, string, NULL)))
			break;

		strcpy(m->id, t);
		m->fd = 0;
	}

	iniparser_freedict(dict);
}

int32_t main(int32_t argc, char *argv[])
{
	uint32_t i;
	sigset_t sigmask;

	g = safe_calloc(sizeof(struct ShareData));
	g->time_start = get_time_usec();
	g->cfg.file = NULL;
	g->client_handler_count = 0;
	g->time_to_die = false;


	/* signal handling all done by a dedicated thread */
	sigemptyset (&sigmask);
	sigaddset (&sigmask, SIGINT);
	sigaddset (&sigmask, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &sigmask, NULL);

	pthread_create(&threads.sighandler, NULL, be_a_signal_handler, &sigmask);

	struct sigaction sa;
	sa.sa_handler = sigusr1_handler;
	sigemptyset(&sa.sa_mask);
	sigaddset (&sigmask, SIGUSR1);
	sa.sa_flags = 0;
	sigaction(SIGUSR1, &sa, NULL);

	if (! (g->threads_to_reap = queue_init()))
	{
		logmsg_f(LOG_CRIT, "queue_init: %s", STR_errno);
		exit(1);
	}
	if (! (g->incoming_clients = queue_init()))
	{
		logmsg_f(LOG_CRIT, "queue_init: %s", STR_errno);
		exit(1);
	}
	if (! (g->replicated_log_entries = queue_init()))
	{
		logmsg_f(LOG_CRIT, "queue_init: %s", STR_errno);
		exit(1);
	}

	/* parse commandline args first (this needs g initialised) */
	parse_cmdline(argc, argv);

	logmsg_f(LOG_NOTICE, "msgiddbd v%s starting up", MSGIDDBD_VERSION);

	g->t = safe_calloc(sizeof(struct tables));
	pthread_mutex_init(&g->t->L_open_tables, NULL);
	g->t->dats_allocated = MAX_OPEN_TABLES;
	g->t->dats = safe_calloc(sizeof(struct dat_files)*g->t->dats_allocated);

	/* init all the pthread_rwlocks now so we don't have to worry about
	 * them later */
	for (i = 0 ; i < g->t->dats_allocated ; i++)
	{
		if (table_lock_init(&g->t->dats[i]))
		{
			logmsg_f(LOG_CRIT, "table_lock_init error");
			abort();
		}
	}

	g->slaves  = safe_calloc(sizeof(struct slave) * MAX_MSGIDDBDS_CONNECTED);
	g->masters = safe_calloc(sizeof(struct master) * MAX_MSGIDDBDS_CONNECTED);

	/* try to read a default config file if none specified */
	if (! g->cfg.file) g->cfg.file = strdup("config.ini");
	read_cfg(g->cfg.file);

	/* open persistent data */
	g->pd = safe_malloc(sizeof(struct persistent_data));
	if (pd_open(g->pd))
	{
		logmsg(LOG_CRIT,
		    "this usually means another msgiddbd is running!");
		exit(1);
	}

	/* we only open a logfile when we get a PUT;
	 * this avoids lots of empty logfiles sitting around
	*/
	logfile_init_struct(&g->l);

	/* check all old logfiles, make sure we didn't crash last time and
	 * have nothing to replay/mark closed etc */
	logfile_check_all();
	
	/* connect to masters; we'll spawn a thread for each one but use a
	 * mutex for updating the database so it's all atomic */
	replication_connect_masters();


	pthread_create(&threads.replication_master,NULL,be_a_replication_master, NULL);

	pthread_create(&threads.reaper, NULL, be_a_thread_reaper, NULL);

	pthread_create(&threads.stats_listen, NULL, be_a_stats_listener, NULL);

	/* set up listening thread */
	pthread_create(&threads.listener, NULL, be_a_listener, NULL);
	pthread_join(threads.listener, NULL);

	/* the join() returns when we're killed */

	logmsg_f(LOG_NOTICE, "msgiddbd starting shutdown");

	/* wait for all clients to go away */
	while(g->open_clients)
	{
		logmsg(LOG_INFO, "%d open clients, waiting..", g->open_clients);
		sleep(2);
	}


	/* client_handler thread killed by sending its queue enough NULLs to
	 * make client_handler_count into zero */
	for(i = 0 ; i < g->client_handler_count ; i++)
		queue_enq(g->incoming_clients, NULL);

	/* no need to pthread_join, be_a_thread_reaper is still running and
	 * doing it for us at this stage */
	while(g->client_handler_count > 0)
	{
		logmsg_f(LOG_INFO, "waiting for client handlers to shut down..");
		sleep(1);
	}
	queue_destroy(g->incoming_clients);

	/* replication master should be safe to kill now, all the clients
	 * are gone which means no more incoming rows */
	queue_enq(g->replicated_log_entries, NULL);
	pthread_join(threads.replication_master, NULL);
	queue_destroy(g->replicated_log_entries);


	pthread_kill(threads.stats_listen, SIGUSR1);
	pthread_join(threads.stats_listen, NULL);


	/* thread reaper killed by sending its queue a NULL */
	queue_enq(g->threads_to_reap, NULL);
	pthread_join(threads.reaper, NULL);
	queue_destroy(g->threads_to_reap);


	/* close/commit log */
	logfile_close(g->l);
	logfile_free_struct(&g->l);

	/* close all tables */
	tables_close_all();

	for (i = 0 ; i < g->t->dats_allocated ; i++)
		table_lock_free(&g->t->dats[i]);

	free(g->t->dats);

	pthread_mutex_destroy(&g->t->L_open_tables);

	free(g->t);

	for(i = 0 ; i < MAX_MSGIDDBDS_CONNECTED ; i++)
	{
		if (g->slaves[i].incoming_rows)
			queue_destroy(g->slaves[i].incoming_rows);
	}
	free(g->slaves);

	for(i = 0 ; i < MAX_MSGIDDBDS_CONNECTED ; i++)
	{
		if (g->masters[i].fd)
		{
			pthread_kill(g->masters[i].thread, SIGUSR1);
			pthread_join(g->masters[i].thread, NULL);
		}
	}
	free(g->masters);

	pd_close(g->pd);
	free(g->pd);

	logmsg_f(LOG_NOTICE, "msgiddbd shutting down cleanly");

	free(g->cfg.dbroot); /* NO FURTHER LOGMSG AFTER THIS FREE */
	free(g->cfg.file);

	free(g);

	return 0;
}
