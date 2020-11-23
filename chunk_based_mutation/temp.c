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
    uint8_t *in_buf;
    int32_t fd, len, n;
    struct stat st;
    lstat("temp.txt", &st);
    len = st.st_size;
    fd = open("temp.txt", O_RDONLY);
    in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (in_buf == MAP_FAILED) {
        printf("map failed\n");
        exit(0);
    }
    
    printf("ljfladjflad\n");
}