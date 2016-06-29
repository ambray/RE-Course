#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

typedef unsigned long long uint64_t;

static int bad_fib(int n)
{
    if(0 == n || 1 == n)
        return n;
    else
        return bad_fib(n - 1) + bad_fib(n - 2);
}

static int good_fib(int n)
{
    int* table = (int*)_alloca((n + 1) * sizeof(int));
    int i = 0;

    if(NULL == (table))
        return -1;
    table[0] = 0;
    table[1] = 1;

    for(i = 2; i <= n; ++i)
        table[i] = table[i - 1] + table[i - 2];

    return table[n];
}

BOOL __declspec(dllexport) __cdecl Lab2a(int n)
{
    LARGE_INTEGER   liOrig = {0};
    LARGE_INTEGER   liNew = {0};
    uint64_t        badFin = 0;
    uint64_t        goodFin = 0;
    int             n1 = 0;
    int             n2 = 0;

    if(!QueryPerformanceCounter(&liOrig)) {
        printf("[x] Failed to get counter value!\n");
        return FALSE;
    }

    n1 = bad_fib(n);

    if(!QueryPerformanceCounter(&liNew) || liNew.QuadPart < liOrig.QuadPart) {
        printf("[x] Failed to get counter value!\n");
        return FALSE;
    }

    badFin = liNew.QuadPart - liOrig.QuadPart;

    memset(&liOrig, 0, sizeof(liOrig));
    memset(&liNew, 0, sizeof(liNew));

    if(!QueryPerformanceCounter(&liOrig)) {
        printf("[x] Failed to get counter value!\n");
        return FALSE;
    }

    n2 = good_fib(n);

    if(!QueryPerformanceCounter(&liNew) || liNew.QuadPart < liOrig.QuadPart) {
        printf("[x] Failed to get counter value!\n");
        return FALSE;
    }

    printf("N1: %d, N2: %d\n", n1, n2);

    goodFin = liNew.QuadPart - liOrig.QuadPart;
    if(goodFin < badFin) {
        printf("2 was %llu faster than 1.\n", badFin-goodFin);
    } else {
        printf("1 was %llu faster than 2.\n", goodFin-badFin);
    }

    return TRUE;
}

int __cdecl main(int argc, char* argv[], char* envp[]) 
{

    Lab2a(20);
    return 0;
}