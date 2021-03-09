#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>   
#include <sys/mman.h>
#include <sys/types.h>    
#include <sys/stat.h>    
#include <fcntl.h>
#include <stdlib.h>

int main() {
    int length, n;
    n = 2147483647;
    length = n * 2 + 6;
    printf("length = %d; n = %d\n", length, n);
}