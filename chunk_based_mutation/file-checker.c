#include <stdio.h>
#include <stdint.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "cJSON.h"

#define alloc_printf(_str...) ({            \
    uint8_t *_tmp;                               \
    int32_t _len = snprintf(NULL, 0, _str);     \
    if (_len < 0)                           \
        perror("Whoa, snprintf() fails?!");  \
    _tmp = calloc(_len + 1, sizeof(char));  \
    snprintf((char *)_tmp, _len + 1, _str); \
    _tmp;                                   \
})

#define CHUNK_START(chunk) ((cJSON *)chunk)->child->valueint
#define CHUNK_END(chunk) ((cJSON *)chunk)->child->next->valueint
#define CHUNK_ID_START(chunk) ((cJSON *)chunk)->child->next->next->child->valueint
#define CHUNK_ID_END(chunk) ((cJSON *)chunk)->child->next->next->child->next->valueint

cJSON *parse_json(const uint8_t *format_file)
{
    cJSON *cjson_head;
    int32_t fd;
    uint8_t *in_buf;
    struct stat st;
    int32_t n;
    if (lstat(format_file, &st))
    {
        printf(format_file);
        printf("lstat error\n");
        exit(0);
    }
    fd = open(format_file, O_RDONLY);
    in_buf = calloc(st.st_size, sizeof(char));
    n = read(fd, in_buf, st.st_size);
    cjson_head = cJSON_Parse(in_buf);
    if (cjson_head == NULL)
    {
        printf("parse fail\n");
        return NULL;
    }
    close(fd);
    free(in_buf);
    return cjson_head;
}

void json_checker(cJSON* cjson_head, uint8_t* file_name) {
    cJSON* cjson_iter;
    cjson_iter = cjson_head->child;
    uint8_t *str;
    if(CHUNK_START(cjson_iter) != 0) {
        str = alloc_printf("first json not zero start, file = %s", file_name);
        perror(str);
    }
    while(cjson_iter) {
        if(CHUNK_START(cjson_iter) == CHUNK_END(cjson_iter)) {
            str = alloc_printf("json zero length, file = %s", file_name);
            perror(str);
        }
        if(cjson_iter->next != NULL) {
            if(CHUNK_END(cjson_iter) != CHUNK_START(cjson_iter->next)) {
                str = alloc_printf("json not continuous, file = %s", file_name);
                perror(str);
            }
        }
        cjson_iter = cjson_iter->next;
    }
}
void file_checker(uint8_t *path) {
    struct dirent **nl;
    int32_t nl_cnt;
    uint32_t i;
    uint8_t* fn;
    uint8_t* str;
    nl_cnt = scandir(path, &nl, NULL, alphasort);
    if(nl_cnt < 0) {
        perror("scandir error");
        exit(0);
    }
    for(uint32_t i = 0; i < nl_cnt; i++) {
        uint8_t* file_type;
        file_type = strrchr(nl[i]->d_name, '.');
        if (file_type != NULL && strcmp(file_type, ".json") == 0) {
            continue;
        }
        struct stat st;
        uint8_t *fn = alloc_printf("%s/%s", path, nl[i]->d_name);
        uint8_t *format_file = alloc_printf("%s/%s.json", path, nl[i]->d_name);

        uint8_t passed_det = 0;

        free(nl[i]); /* not tracked */

        if (lstat(fn, &st) || access(fn, R_OK)) {
            perror("Unable to access file"); 
            exit(0);
        }

        if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn, "/README.txt")) {
            free(fn);
            continue;
        }

        cJSON* cjson_head = parse_json(format_file);
        json_checker(cjson_head, fn);
        cJSON* cjson_iter;
        uint32_t cjson_len;
        cjson_iter = cjson_head->child;
        if(cjson_iter == NULL) {
            cjson_len = 0;
        }else {
            while(cjson_iter->next) {
                cjson_iter = cjson_iter->next;
            }
            cjson_len = CHUNK_END(cjson_iter);
        }
        if(cjson_len != st.st_size) {
            str = alloc_printf("cjson len != file len, file = %s", fn);
            perror(str);
        }
    }
}

int main(int argc, char* argv[]) {
    file_checker(argv[1]);
    printf("check over!!!!!!!!!!!!!!!!!!!\n");
}