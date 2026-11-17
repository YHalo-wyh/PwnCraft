#include <stdio.h>

static void read_name(void) {
    char name[64];
    puts("PwnCraft GUI demo: enter a name");
    if (fgets(name, sizeof(name), stdin)) {
        printf("Hello, %s", name);
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    read_name();
    return 0;
}
