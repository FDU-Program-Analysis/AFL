#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>    
#include <fcntl.h>  
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "cJSON.h"

#define CHUNK_START(chunk) ((cJSON *)chunk)->child->valueint
#define CHUNK_END(chunk) ((cJSON *)chunk)->child->next->valueint

cJSON* parse_json(const uint8_t* format_file) {
    cJSON* cjson_head;
    int32_t fd;
    uint8_t *in_buf;
    struct stat st;
    int32_t n;
    if(lstat(format_file, &st)) {
        printf("lstat error\n");
        exit(0);
    }
    fd = open(format_file, O_RDONLY);
    in_buf = malloc(st.st_size);
    n = read(fd, in_buf, st.st_size);
    cjson_head = cJSON_Parse(in_buf);
    if(cjson_head == NULL) {
        printf("parse fail\n");
        return NULL;
    }
    close(fd);
    free(in_buf);
    printf("%d, %d;", CHUNK_START(cjson_head->child), CHUNK_END(cjson_head->child));
    return cjson_head;
}

void insert_chunk(uint8_t* buf, cJSON* cjson_head, uint32_t chunk_index, uint32_t insert_index) {
    uint32_t clone_from, clone_to, clone_len;
    cJSON *cjson_iter;

    cJSON* chunk_choose = cjson_head->child;
    for(int i = 0; i < chunk_index; i++) {
        chunk_choose = chunk_choose->next;
    }

    clone_len = CHUNK_END(chunk_choose) - CHUNK_START(chunk_choose) + 1;
    uint8_t* new_buf;
    new_buf = malloc(strlen(buf) + clone_len);

    if(insert_index == 0) {
        clone_to = 0;
    }else {
        cJSON *chunk_insert = cjson_head->child;
        for (int i = 0; i < insert_index - 1; i++) {
            chunk_insert = chunk_insert->next;
        }
        clone_to = CHUNK_END(chunk_insert) + 1;
    }
    memcpy(new_buf, buf, clone_to);
    memcpy(new_buf + clone_to, buf + CHUNK_START(chunk_choose), clone_len);
    memcpy(new_buf + clone_to + clone_len, buf + clone_to, strlen(buf) - clone_to);

    cJSON* chunk_dup = cJSON_Duplicate(chunk_choose, 1);
    cJSON_InsertItemInArray(cjson_head, insert_index, chunk_dup);

    cJSON_SetIntValue(chunk_dup->child, clone_to);
    cJSON_SetIntValue(chunk_dup->child->next, CHUNK_START(chunk_dup) + clone_len - 1);
    cjson_iter = chunk_dup->next;
    while(cjson_iter) {
        cJSON_SetIntValue(cjson_iter->child, CHUNK_START(cjson_iter) + clone_len);
        cJSON_SetIntValue(cjson_iter->child->next, CHUNK_END(cjson_iter) + clone_len);
        cjson_iter = cjson_iter->next;
    }

    printf(new_buf);
    // cJSON_Delete(cjson_head);
}

void delete_chunk(uint8_t* buf, cJSON* cjson_head, uint32_t delete_index) {
    uint32_t clone_from, clone_to, clone_len;
    cJSON *cjson_iter;
    cJSON* chunk_delete = cjson_head->child;
    for(int i = 0; i < delete_index; i++) {
        chunk_delete = chunk_delete->next;
    }
    uint32_t delete_len = CHUNK_END(chunk_delete) - CHUNK_START(chunk_delete) + 1;
    uint8_t* new_buf;
    new_buf = malloc(strlen(buf) - delete_len);
    clone_to = CHUNK_START(chunk_delete);
    memcpy(new_buf, buf, clone_to);
    memcpy(new_buf + clone_to, buf + clone_to + delete_len, strlen(buf) - clone_to - delete_len);

    cjson_iter = chunk_delete->next;
    while (cjson_iter) {
        cJSON_SetIntValue(cjson_iter->child, CHUNK_START(cjson_iter) - delete_len);
        cJSON_SetIntValue(cjson_iter->child->next, CHUNK_END(cjson_iter) - delete_len);
        cjson_iter = cjson_iter->next;
    }

    cJSON_DetachItemViaPointer(cjson_head, chunk_delete);

    // cJSON_Delete(cjson_head);
}

void exchange_chunk(uint32_t index1, uint32_t index2) {
    
}

void write_to_file(cJSON* cjson_head) {
    uint8_t *cjson_str = cJSON_Print(cjson_head);
    uint32_t fd;
    fd = open("temp.json", O_WRONLY | O_CREAT | O_EXCL, 0600);
    write(fd, cjson_str, strlen(cjson_str));
}

uint32_t chunk_total(cJSON* cjson_head) {
    cJSON *cjson_iter;
    cjson_iter = cjson_head->child;
    uint32_t chunk_total = 0;
    while (cjson_iter){
        chunk_total++;
        cjson_iter = cjson_iter->next;
    }
    return chunk_total;
}

int main() {
    uint8_t *in_buf;
    int32_t fd, len;
    uint32_t clone_from, clone_to, clone_len;
    fd = open("input.txt", O_RDONLY);
    len = 16;
    in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    cJSON *cjson_head, *cjson_temp;

    cjson_head = parse_json("input.txt.json");
    cjson_temp = parse_json("input.txt.json");
    insert_chunk(in_buf, cjson_head, 0, 0);

    printf(cJSON_Print(cjson_temp));
    printf("%d", cJSON_Compare(cjson_head, cjson_temp, 1));

    delete_chunk(in_buf, cjson_head, 0);

    write_to_file(cjson_head);
}