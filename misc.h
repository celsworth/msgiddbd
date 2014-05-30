#pragma once

#define atomic_inc_32(i) atomic_add_32(&i, 1)
#define atomic_dec_32(i) atomic_subtract_32(&i, 1)
#define atomic_inc_64(i) atomic_add_64(&i, 1)
#define atomic_dec_64(i) atomic_subtract_64(&i, 1)

void *safe_realloc(void *, size_t);
void *safe_calloc(size_t);
void *safe_malloc(size_t);
ssize_t sockwrite(int32_t, const char *, ...);

time_t get_time_usec(void);

char *basename_r(const char *, char *);

//int make_full_path(char *, char *, ...);
//int make_full_logpath(char *, char *, ...);
