#include <stdio.h>
#include <unistd.h>

// __attribute__((section(".rodata"))) 
// char big_buffer[10 * 1024 * 1024]; // 100MB trong data segment

int main() {
    printf("This is a large executable test.\n");
    while(1) {
        sleep(1);
    }
    return 0;
}