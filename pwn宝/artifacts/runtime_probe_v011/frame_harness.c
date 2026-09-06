#include <stdio.h>
__attribute__((noinline)) int vuln(int x) { volatile int y = x + 7; return y; }
__attribute__((noinline)) int foo(int x) { return vuln(x) + 1; }
int main(void) { printf("%d\n", foo(3)); return 0; }
