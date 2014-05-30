CC?=gcc
CFLAGS=-pipe -g -Wall -Wextra -Wshadow -DX86
LDFLAGS=-Liniparser3.0b -liniparser -pthread
DEPEND=makedepend

SOURCES=misc.c logmsg.c logfile.c table.c client.c html.c thrqueue.c msgiddbd.c
HEADERS=$(SOURCES:.c=.h)
OBJECTS=$(SOURCES:.c=.o)

all:	msgiddbd

clean:
	-rm msgiddbd *.o

depend:
	$(DEPEND) $(SOURCES)

msgiddbd: $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o $@

#.c.o: $(HEADERS)
#	$(CC) $(CFLAGS) -c $<


# DO NOT DELETE

misc.o: includes.h /usr/include/dirent.h /usr/include/sys/cdefs.h
misc.o: /usr/include/sys/dirent.h /usr/include/sys/_types.h
misc.o: /usr/include/machine/_types.h /usr/include/sys/_null.h
misc.o: /usr/include/errno.h /usr/include/fcntl.h /usr/include/netdb.h
misc.o: /usr/include/pthread.h /usr/include/sys/_pthreadtypes.h
misc.o: /usr/include/machine/_limits.h /usr/include/sys/_sigset.h
misc.o: /usr/include/sched.h /usr/include/time.h /usr/include/sys/timespec.h
misc.o: /usr/include/signal.h /usr/include/sys/signal.h
misc.o: /usr/include/machine/signal.h /usr/include/machine/trap.h
misc.o: /usr/include/stdarg.h /usr/include/stdbool.h /usr/include/stdio.h
misc.o: /usr/include/stdlib.h /usr/include/string.h /usr/include/strings.h
misc.o: /usr/include/sys/types.h /usr/include/machine/endian.h
misc.o: /usr/include/sys/select.h /usr/include/sys/_timeval.h
misc.o: /usr/include/sys/event.h /usr/include/sys/queue.h
misc.o: /usr/include/sys/mman.h /usr/include/sys/mount.h
misc.o: /usr/include/sys/ucred.h /usr/include/bsm/audit.h
misc.o: /usr/include/sys/param.h /usr/include/sys/syslimits.h
misc.o: /usr/include/machine/param.h /usr/include/sys/limits.h
misc.o: /usr/include/sys/socket.h /usr/include/sys/_iovec.h
misc.o: /usr/include/sys/stat.h /usr/include/sys/time.h /usr/include/syslog.h
misc.o: /usr/include/unistd.h /usr/include/sys/unistd.h
misc.o: /usr/include/machine/atomic.h defines.h msgiddbd.h misc.h
logmsg.o: includes.h /usr/include/dirent.h /usr/include/sys/cdefs.h
logmsg.o: /usr/include/sys/dirent.h /usr/include/sys/_types.h
logmsg.o: /usr/include/machine/_types.h /usr/include/sys/_null.h
logmsg.o: /usr/include/errno.h /usr/include/fcntl.h /usr/include/netdb.h
logmsg.o: /usr/include/pthread.h /usr/include/sys/_pthreadtypes.h
logmsg.o: /usr/include/machine/_limits.h /usr/include/sys/_sigset.h
logmsg.o: /usr/include/sched.h /usr/include/time.h
logmsg.o: /usr/include/sys/timespec.h /usr/include/signal.h
logmsg.o: /usr/include/sys/signal.h /usr/include/machine/signal.h
logmsg.o: /usr/include/machine/trap.h /usr/include/stdarg.h
logmsg.o: /usr/include/stdbool.h /usr/include/stdio.h /usr/include/stdlib.h
logmsg.o: /usr/include/string.h /usr/include/strings.h
logmsg.o: /usr/include/sys/types.h /usr/include/machine/endian.h
logmsg.o: /usr/include/sys/select.h /usr/include/sys/_timeval.h
logmsg.o: /usr/include/sys/event.h /usr/include/sys/queue.h
logmsg.o: /usr/include/sys/mman.h /usr/include/sys/mount.h
logmsg.o: /usr/include/sys/ucred.h /usr/include/bsm/audit.h
logmsg.o: /usr/include/sys/param.h /usr/include/sys/syslimits.h
logmsg.o: /usr/include/machine/param.h /usr/include/sys/limits.h
logmsg.o: /usr/include/sys/socket.h /usr/include/sys/_iovec.h
logmsg.o: /usr/include/sys/stat.h /usr/include/sys/time.h
logmsg.o: /usr/include/syslog.h /usr/include/unistd.h
logmsg.o: /usr/include/sys/unistd.h /usr/include/machine/atomic.h defines.h
logmsg.o: msgiddbd.h logmsg.h
logfile.o: includes.h /usr/include/dirent.h /usr/include/sys/cdefs.h
logfile.o: /usr/include/sys/dirent.h /usr/include/sys/_types.h
logfile.o: /usr/include/machine/_types.h /usr/include/sys/_null.h
logfile.o: /usr/include/errno.h /usr/include/fcntl.h /usr/include/netdb.h
logfile.o: /usr/include/pthread.h /usr/include/sys/_pthreadtypes.h
logfile.o: /usr/include/machine/_limits.h /usr/include/sys/_sigset.h
logfile.o: /usr/include/sched.h /usr/include/time.h
logfile.o: /usr/include/sys/timespec.h /usr/include/signal.h
logfile.o: /usr/include/sys/signal.h /usr/include/machine/signal.h
logfile.o: /usr/include/machine/trap.h /usr/include/stdarg.h
logfile.o: /usr/include/stdbool.h /usr/include/stdio.h /usr/include/stdlib.h
logfile.o: /usr/include/string.h /usr/include/strings.h
logfile.o: /usr/include/sys/types.h /usr/include/machine/endian.h
logfile.o: /usr/include/sys/select.h /usr/include/sys/_timeval.h
logfile.o: /usr/include/sys/event.h /usr/include/sys/queue.h
logfile.o: /usr/include/sys/mman.h /usr/include/sys/mount.h
logfile.o: /usr/include/sys/ucred.h /usr/include/bsm/audit.h
logfile.o: /usr/include/sys/param.h /usr/include/sys/syslimits.h
logfile.o: /usr/include/machine/param.h /usr/include/sys/limits.h
logfile.o: /usr/include/sys/socket.h /usr/include/sys/_iovec.h
logfile.o: /usr/include/sys/stat.h /usr/include/sys/time.h
logfile.o: /usr/include/syslog.h /usr/include/unistd.h
logfile.o: /usr/include/sys/unistd.h /usr/include/machine/atomic.h defines.h
logfile.o: msgiddbd.h misc.h logmsg.h table.h logfile.h thrqueue.h
table.o: includes.h /usr/include/dirent.h /usr/include/sys/cdefs.h
table.o: /usr/include/sys/dirent.h /usr/include/sys/_types.h
table.o: /usr/include/machine/_types.h /usr/include/sys/_null.h
table.o: /usr/include/errno.h /usr/include/fcntl.h /usr/include/netdb.h
table.o: /usr/include/pthread.h /usr/include/sys/_pthreadtypes.h
table.o: /usr/include/machine/_limits.h /usr/include/sys/_sigset.h
table.o: /usr/include/sched.h /usr/include/time.h /usr/include/sys/timespec.h
table.o: /usr/include/signal.h /usr/include/sys/signal.h
table.o: /usr/include/machine/signal.h /usr/include/machine/trap.h
table.o: /usr/include/stdarg.h /usr/include/stdbool.h /usr/include/stdio.h
table.o: /usr/include/stdlib.h /usr/include/string.h /usr/include/strings.h
table.o: /usr/include/sys/types.h /usr/include/machine/endian.h
table.o: /usr/include/sys/select.h /usr/include/sys/_timeval.h
table.o: /usr/include/sys/event.h /usr/include/sys/queue.h
table.o: /usr/include/sys/mman.h /usr/include/sys/mount.h
table.o: /usr/include/sys/ucred.h /usr/include/bsm/audit.h
table.o: /usr/include/sys/param.h /usr/include/sys/syslimits.h
table.o: /usr/include/machine/param.h /usr/include/sys/limits.h
table.o: /usr/include/sys/socket.h /usr/include/sys/_iovec.h
table.o: /usr/include/sys/stat.h /usr/include/sys/time.h
table.o: /usr/include/syslog.h /usr/include/unistd.h
table.o: /usr/include/sys/unistd.h /usr/include/machine/atomic.h defines.h
table.o: msgiddbd.h misc.h logmsg.h table.h logfile.h
client.o: includes.h /usr/include/dirent.h /usr/include/sys/cdefs.h
client.o: /usr/include/sys/dirent.h /usr/include/sys/_types.h
client.o: /usr/include/machine/_types.h /usr/include/sys/_null.h
client.o: /usr/include/errno.h /usr/include/fcntl.h /usr/include/netdb.h
client.o: /usr/include/pthread.h /usr/include/sys/_pthreadtypes.h
client.o: /usr/include/machine/_limits.h /usr/include/sys/_sigset.h
client.o: /usr/include/sched.h /usr/include/time.h
client.o: /usr/include/sys/timespec.h /usr/include/signal.h
client.o: /usr/include/sys/signal.h /usr/include/machine/signal.h
client.o: /usr/include/machine/trap.h /usr/include/stdarg.h
client.o: /usr/include/stdbool.h /usr/include/stdio.h /usr/include/stdlib.h
client.o: /usr/include/string.h /usr/include/strings.h
client.o: /usr/include/sys/types.h /usr/include/machine/endian.h
client.o: /usr/include/sys/select.h /usr/include/sys/_timeval.h
client.o: /usr/include/sys/event.h /usr/include/sys/queue.h
client.o: /usr/include/sys/mman.h /usr/include/sys/mount.h
client.o: /usr/include/sys/ucred.h /usr/include/bsm/audit.h
client.o: /usr/include/sys/param.h /usr/include/sys/syslimits.h
client.o: /usr/include/machine/param.h /usr/include/sys/limits.h
client.o: /usr/include/sys/socket.h /usr/include/sys/_iovec.h
client.o: /usr/include/sys/stat.h /usr/include/sys/time.h
client.o: /usr/include/syslog.h /usr/include/unistd.h
client.o: /usr/include/sys/unistd.h /usr/include/machine/atomic.h defines.h
client.o: msgiddbd.h misc.h logfile.h client.h logmsg.h table.h thrqueue.h
client.o: html.h
html.o: /usr/include/stdio.h /usr/include/sys/cdefs.h
html.o: /usr/include/sys/_null.h /usr/include/sys/_types.h
html.o: /usr/include/machine/_types.h /usr/include/stdlib.h
html.o: /usr/include/string.h /usr/include/strings.h html.h
thrqueue.o: /usr/include/pthread.h /usr/include/sys/cdefs.h
thrqueue.o: /usr/include/sys/_pthreadtypes.h /usr/include/machine/_limits.h
thrqueue.o: /usr/include/machine/_types.h /usr/include/sys/_sigset.h
thrqueue.o: /usr/include/sched.h /usr/include/sys/_types.h
thrqueue.o: /usr/include/time.h /usr/include/sys/_null.h
thrqueue.o: /usr/include/sys/timespec.h /usr/include/assert.h
thrqueue.o: /usr/include/stdio.h /usr/include/stdlib.h thrqueue.h
thrqueue.o: /usr/include/sys/queue.h
msgiddbd.o: includes.h /usr/include/dirent.h /usr/include/sys/cdefs.h
msgiddbd.o: /usr/include/sys/dirent.h /usr/include/sys/_types.h
msgiddbd.o: /usr/include/machine/_types.h /usr/include/sys/_null.h
msgiddbd.o: /usr/include/errno.h /usr/include/fcntl.h /usr/include/netdb.h
msgiddbd.o: /usr/include/pthread.h /usr/include/sys/_pthreadtypes.h
msgiddbd.o: /usr/include/machine/_limits.h /usr/include/sys/_sigset.h
msgiddbd.o: /usr/include/sched.h /usr/include/time.h
msgiddbd.o: /usr/include/sys/timespec.h /usr/include/signal.h
msgiddbd.o: /usr/include/sys/signal.h /usr/include/machine/signal.h
msgiddbd.o: /usr/include/machine/trap.h /usr/include/stdarg.h
msgiddbd.o: /usr/include/stdbool.h /usr/include/stdio.h /usr/include/stdlib.h
msgiddbd.o: /usr/include/string.h /usr/include/strings.h
msgiddbd.o: /usr/include/sys/types.h /usr/include/machine/endian.h
msgiddbd.o: /usr/include/sys/select.h /usr/include/sys/_timeval.h
msgiddbd.o: /usr/include/sys/event.h /usr/include/sys/queue.h
msgiddbd.o: /usr/include/sys/mman.h /usr/include/sys/mount.h
msgiddbd.o: /usr/include/sys/ucred.h /usr/include/bsm/audit.h
msgiddbd.o: /usr/include/sys/param.h /usr/include/sys/syslimits.h
msgiddbd.o: /usr/include/machine/param.h /usr/include/sys/limits.h
msgiddbd.o: /usr/include/sys/socket.h /usr/include/sys/_iovec.h
msgiddbd.o: /usr/include/sys/stat.h /usr/include/sys/time.h
msgiddbd.o: /usr/include/syslog.h /usr/include/unistd.h
msgiddbd.o: /usr/include/sys/unistd.h /usr/include/machine/atomic.h defines.h
msgiddbd.o: msgiddbd.h misc.h logfile.h client.h logmsg.h table.h thrqueue.h
msgiddbd.o: html.h prototypes.h iniparser3.0b/src/iniparser.h
msgiddbd.o: iniparser3.0b/src/dictionary.h
