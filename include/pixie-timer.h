#ifndef PIXIE_TIMER_H
#define PIXIE_TIMER_H
#include <stdint.h>


uint64_t pixie_gettime(void);


uint64_t pixie_nanotime(void);


void pixie_usleep(uint64_t usec);


void pixie_mssleep(unsigned milliseconds);


int pixie_time_selftest(void);




#endif
