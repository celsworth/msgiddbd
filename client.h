#pragma once

#define PUT_NOFLAGS   0
#define PUT_CHECKDUPE 1

/* return codes client_slave_read_command */
#define E_CLIENT_SLAVE_STOP 1

/* response codes for sending to clients */
#define RESPONSE_200 "200 DONE"
#define RESPONSE_201 "201 OK, preparing stats"
#define RESPONSE_206 "206 checked ok" /* table checked ok */
#define RESPONSE_210 "210 replication starting at file=%s offset=%lu"
#define RESPONSE_211 "211 OK, replication stopped"
#define RESPONSE_290 "290 OK, daemon death impending"
#define RESPONSE_299 "299 Have a nice day!"
#define RESPONSE_300 "300 nothing in log buffer to commit"
#define RESPONSE_310 "310 segment already exists"
#define RESPONSE_404 "404 FILEID %lu" /* file or table not found */
#define RESPONSE_500 "500 What?"
#define RESPONSE_501 "501 FILEID %lu" /* variety of internal errors */
#define RESPONSE_502 "502 syntax incorrect" /* PUT syntax incorrect */
/* 503 size/segment out of bounds */
#define RESPONSE_504 "504 internal logfile error"
#define RESPONSE_505 "505 PUTs are disabled"
#define RESPONSE_506 "506 your server_id is already slaved"
#define RESPONSE_507 "507 unexpected format, use SLAVE <server_id> <log_file> <log_pos>"
#define RESPONSE_508 "508 error adding slave"
#define RESPONSE_510 "510 invalid logfile, not found or corrupt"
#define RESPONSE_511 "511 logfile isn't big enough to start there"
#define RESPONSE_520 "520 replication stopped for unknown reason"

struct client
{
	fd_t client_fd;
	struct logfile_buffer *logbuf;
};

struct child_info
{
	pthread_t thread;
};

int32_t segment_sort(const void *, const void *);

int32_t client_do_send_fileid(fd_t, fileid_t);
void client_do_get(struct client *, char *);
void client_do_commit(struct client *, char *);
int split_put(char *, struct segment_local *);
void client_do_put(struct client *, char *, int32_t);
void client_do_stats(struct client *, const char *);
int32_t client_slave_send_rows_from_buf(struct slave *, struct logfile_entry *, log_count_t, ssize_t);
int32_t client_slave_read_and_send_rows(struct slave *, struct logfile *, ssize_t, ssize_t);
int32_t client_slave_open_log(struct slave *, struct logfile *);
int32_t client_slave_do_log(struct slave *, struct logfile *, ssize_t);
int32_t client_slave_catchup(struct slave *, char *, ssize_t);
void client_slave_disconnecting(struct slave *);
void *be_a_slave_cmd_reader(void *);
void client_do_slave(struct client *, const char *);
void client_do_check(struct client *, const char *);
int handle_a_client(void *);
void *be_a_client_handler(void *);
