#include <stdlib.h>
__attribute__((noinline)) void marker(void *p) { __asm__ volatile("" : : "r"(p) : "memory"); }
int main(void) { void *a=malloc(0x30); void *b=malloc(0x80); free(a); marker(b); free(b); return 0; }
