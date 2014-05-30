#pragma once

#define logmsg(pri, fmt, ...) real_logmsg(pri, NULL, 0, fmt, ## __VA_ARGS__)
#define logmsg_f(pri, fmt, ...) real_logmsg(pri, __func__, 0, fmt, ## __VA_ARGS__)
#define logmsg_fl(pri, fmt, ...) real_logmsg(pri, __func__, __LINE__, fmt, ## __VA_ARGS__)

void logmsg_sprinttime(char *);
void real_logmsg(int32_t, const char *, int, char *, ...);
