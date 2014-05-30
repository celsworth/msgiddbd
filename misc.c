#include "includes.h"
#include "defines.h"

#include "msgiddbd.h"
#include "misc.h"

extern struct ShareData *g;

void *safe_realloc(void *o, size_t size)
{
	void *m = realloc(o, size);
	if (!m)
	{
		perror("realloc");
		exit(255);
	}
	return m;
}
void *safe_calloc(size_t size)
{
	void *m = calloc(size, 1);
	if (!m)
	{
		perror("calloc");
		exit(255);
	}
	return m;
}
void *safe_malloc(size_t size)
{
	void *m = malloc(size);
	if (!m)
	{
		perror("malloc");
		exit(255);
	}
	return m;
}

/* write the formatted string fmt and it's arguments into the socket d */
ssize_t sockwrite(fd_t d, const char *fmt, ...)
{
	int32_t n;
	char buf[SOCK_BUFSIZE + 3];
	va_list ap;
	va_start(ap, fmt);
	n = vsnprintf(buf, SOCK_BUFSIZE + 3, fmt, ap);
	va_end(ap);

#if DEBUG_LOG_TRAFFIC
	logmsg(LOG_DEBUG, "fd=%d >> %.*s", d, n, buf);
#endif

	buf[n++] = '\n';
	buf[n] = '\0';

	return send(d, buf, n, 0);
}

time_t get_time_usec(void) /* {{{ */
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000000 + tv.tv_usec;
} /* }}} */

/* basename_r: a thread-safe non-allocating version of basename {{{ */
char *basename_r(const char *path, char *bname)
{
	const char *endp, *startp;

	/* Empty or NULL string gets treated as "." */
	if (path == NULL || *path == '\0') {
		(void)strcpy(bname, ".");
		return(bname);
	}

	/* Strip trailing slashes */
	endp = path + strlen(path) - 1;
	while (endp > path && *endp == '/')
		endp--;

	/* All slashes becomes "/" */
	if (endp == path && *endp == '/') {
		(void)strcpy(bname, "/");
		return(bname);
	}

	/* Find the start of the base */
	startp = endp;
	while (startp > path && *(startp - 1) != '/')
		startp--;

	if (endp - startp + 2 > MAXPATHLEN) {
		errno = ENAMETOOLONG;
		return(NULL);
	}
	(void)strncpy(bname, startp, endp - startp + 1);
	bname[endp - startp + 1] = '\0';
	return(bname);
} /* }}} */

#if 0
int make_full_path(char *buf, char *fmt, ...) /* {{{ */
{
	va_list args;
	uint32_t buf_left = PATH_MAX;
	char internalbuf[PATH_MAX], *p = internalbuf;

	va_start(args, fmt);

	strcpy(p, g->cfg.local_dbroot);
	p += g->cfg.local_dbroot_len;
	buf_left -= g->cfg.local_dbroot_len;

	/* cope with dbroot having no trailing slash */
	*p++ = '/';
	buf_left--;

	p += vsnprintf(p, buf_left, fmt, args);
	buf_left -= (p - buf);

	realpath(internalbuf, buf);

	va_end(args);

	return 0;
} /* }}} */
int make_full_logpath(char *buf, char *fmt, ...) /* {{{ */
{
	va_list args;
	uint32_t buf_left = PATH_MAX;
	char internalbuf[PATH_MAX], *p = internalbuf;

	va_start(args, fmt);

	strcpy(p, g->cfg.local_logdir);
	p += g->cfg.local_logdir_len;
	buf_left -= g->cfg.local_logdir_len;

	/* cope with logdir having no trailing slash */
	*p++ = '/';
	buf_left--;

	p += vsnprintf(p, buf_left, fmt, args);
	buf_left -= (p - buf);

	realpath(internalbuf, buf);

	va_end(args);

	return 0;
} /* }}} */
#endif
