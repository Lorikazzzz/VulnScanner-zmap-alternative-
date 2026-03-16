#ifndef RAND_BLACKROCK_H
#define RAND_BLACKROCK_H
#include <stdint.h>

struct BlackRock {
    uint64_t range;
    uint64_t a;
    uint64_t b;
    uint64_t seed;
    unsigned rounds;
    uint64_t a_bits;
    uint64_t a_mask;
    uint64_t b_bits;
    uint64_t b_mask;
};


void
blackrock_init(struct BlackRock *br, uint64_t range, uint64_t seed, unsigned rounds);
void
blackrock2_init(struct BlackRock *br, uint64_t range, uint64_t seed, unsigned rounds);


uint64_t
blackrock_shuffle(const struct BlackRock *br, uint64_t index);
uint64_t
blackrock2_shuffle(const struct BlackRock *br, uint64_t index);


uint64_t
blackrock_unshuffle(const struct BlackRock *br, uint64_t m);
uint64_t
blackrock2_unshuffle(const struct BlackRock *br, uint64_t m);



int
blackrock_selftest(void);
int
blackrock2_selftest(void);


void
blackrock_benchmark(unsigned rounds);
void
blackrock2_benchmark(unsigned rounds);

#endif
