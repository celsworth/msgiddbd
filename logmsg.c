#include "includes.h"
#include "defines.h"

#include "msgiddbd.h"

#include "logmsg.h"

extern struct ShareData *g;
extern int8_t cfg_foreground;

#define FMT_DATE_LENGTH 512
#define FMT_MSG_LENGTH 512
void logmsg_sprinttime(char *date)
{
	struct tm now_tm;
	struct timeval tp;

	gettimeofday(&tp, NULL);
	localtime_r(&tp.tv_sec, &now_tm);

	snprintf(date, FMT_DATE_LENGTH,
	  "%04d-%02d-%02d %02d:%02d:%02d.%03lu ",
	  now_tm.tm_year+1900, now_tm.tm_mon+1, now_tm.tm_mday,
	  now_tm.tm_hour,now_tm.tm_min,now_tm.tm_sec,tp.tv_usec/1000);
}
void real_logmsg(int32_t priority, const char *func, int line, char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	char date[FMT_DATE_LENGTH];
	char msg[FMT_MSG_LENGTH];
	char *p = msg;

	if (func)
	{
		p += sprintf(p, func);

		if (line)
			p += sprintf(p, ":%d", line);

		p += sprintf(p, ": ");
	}

	vsnprintf(p, FMT_MSG_LENGTH, fmt, args);

	if (cfg_foreground)
	{
		logmsg_sprinttime(date);
		printf("%s%s\n", date, msg);

		/* additionally, log anything greater than
		 * LOG_DEBUG/LOG_INFO to a file so we don't lose it in
		 * scrollback */
		if (priority != LOG_DEBUG && priority != LOG_INFO)
		{
			int lfd;
			char log[128];
			sprintf(log, "%s/msgiddbd.log", g->cfg.dbroot);
			lfd = open(log,
			    O_WRONLY | O_EXLOCK | O_CREAT | O_APPEND,
			    (mode_t)0644);
			if (lfd > 0)
			{
				write(lfd, date, strlen(date));
				write(lfd, msg, strlen(msg));
				write(lfd, "\n", 1);
				close(lfd);
			}
		}
	}
	else if (priority != LOG_DEBUG)
		syslog(priority, msg);


	va_end(args);
	return;
}
