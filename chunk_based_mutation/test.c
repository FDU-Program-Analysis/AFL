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
    return cjson_head;
}

uint8_t* insert_chunk(uint8_t* buf, uint32_t *len, cJSON* cjson_head, uint32_t chunk_index, uint32_t insert_index) {
    uint32_t clone_from, clone_to, clone_len;
    cJSON *cjson_iter;

    cJSON* chunk_choose = cjson_head->child;
    for(int i = 0; i < chunk_index; i++) {
        chunk_choose = chunk_choose->next;
    }

    clone_len = CHUNK_END(chunk_choose) - CHUNK_START(chunk_choose);
    uint8_t* new_buf;
    new_buf = (uint8_t *)calloc(0, strlen(buf) + clone_len);
    if(insert_index == 0) {
        clone_to = 0;
    }else {
        cJSON *chunk_insert = cjson_head->child;
        for (int i = 0; i < insert_index - 1; i++) {
            chunk_insert = chunk_insert->next;
        }
        clone_to = CHUNK_END(chunk_insert);
    }
    memcpy(new_buf, buf, clone_to);
    memcpy(new_buf + clone_to, buf + CHUNK_START(chunk_choose), clone_len);
    memcpy(new_buf + clone_to + clone_len, buf + clone_to, strlen(buf) - clone_to);
    *len += clone_len;

    cJSON* chunk_dup = cJSON_Duplicate(chunk_choose, 1);
    cJSON_InsertItemInArray(cjson_head, insert_index, chunk_dup);

    cJSON_SetIntValue(chunk_dup->child, clone_to);
    cJSON_SetIntValue(chunk_dup->child->next, CHUNK_START(chunk_dup) + clone_len);
    cjson_iter = chunk_dup->next;
    while(cjson_iter) {
        cJSON_SetIntValue(cjson_iter->child, CHUNK_START(cjson_iter) + clone_len);
        cJSON_SetIntValue(cjson_iter->child->next, CHUNK_END(cjson_iter) + clone_len);
        cjson_iter = cjson_iter->next;
    }

    free(buf);
    return new_buf;
}

uint8_t* delete_chunk(uint8_t* buf, cJSON* cjson_head, uint32_t delete_index) {
    uint32_t clone_from, clone_to, clone_len;
    cJSON *cjson_iter;
    cJSON* chunk_delete = cjson_head->child;
    for(int i = 0; i < delete_index; i++) {
        chunk_delete = chunk_delete->next;
    }
    uint32_t delete_len = CHUNK_END(chunk_delete) - CHUNK_START(chunk_delete);
    uint8_t* new_buf;
    new_buf = calloc(0, strlen(buf) - delete_len);
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

    free(buf);
    return new_buf;
}

uint8_t* exchange_chunk(uint8_t* buf, uint32_t len, cJSON* cjson_head, uint32_t index1, uint32_t index2) {
    cJSON* cjson_iter;
    cJSON* cjson_fro;
    cJSON* cjson_aft;
    uint32_t temp;
    if(index1 == index2) {
        return;
    }
    if(index2 < index1) {
        temp = index1;
        index1 = index2;
        index2 = temp;
    }
    cjson_fro = cjson_head->child;
    for(uint32_t i = 0; i < index1; i++) {
        cjson_fro = cjson_fro->next;
    }
    cjson_aft = cjson_fro;
    for(uint32_t i = index1; i < index2; i++) {
        cjson_aft = cjson_aft->next;
    }
    cJSON_DetachItemViaPointer(cjson_head, cjson_fro);
    cJSON_DetachItemViaPointer(cjson_head, cjson_aft);

    cJSON_InsertItemInArray(cjson_head, index1, cjson_aft);
    cJSON_InsertItemInArray(cjson_head, index2, cjson_fro);

    uint8_t *new_buf;
    new_buf = calloc(0, len);
    memcpy(new_buf, buf, CHUNK_START(cjson_fro));
    memcpy(new_buf + CHUNK_START(cjson_fro), buf + CHUNK_START(cjson_aft), CHUNK_END(cjson_aft) - CHUNK_START(cjson_aft));
    memcpy(new_buf + CHUNK_START(cjson_fro) + CHUNK_END(cjson_aft) - CHUNK_START(cjson_aft), buf + CHUNK_END(cjson_fro), CHUNK_START(cjson_aft) - CHUNK_END(cjson_fro));
    memcpy(new_buf + CHUNK_START(cjson_fro) + CHUNK_END(cjson_aft) - CHUNK_END(cjson_fro), buf + CHUNK_START(cjson_fro), CHUNK_END(cjson_fro) - CHUNK_START(cjson_fro));
    memcpy(new_buf + CHUNK_END(cjson_aft), buf + CHUNK_END(cjson_aft), len - CHUNK_END(cjson_aft));
    uint32_t aft_end;
    aft_end = CHUNK_END(cjson_aft);
    cJSON_SetIntValue(cjson_aft->child->next, CHUNK_START(cjson_fro) + CHUNK_END(cjson_aft) - CHUNK_START(cjson_aft));
    cJSON_SetIntValue(cjson_aft->child, CHUNK_START(cjson_fro));
    cjson_iter = cjson_aft->next;
    uint32_t gap = CHUNK_END(cjson_aft) - CHUNK_START(cjson_aft) - CHUNK_END(cjson_fro) + CHUNK_START(cjson_fro);
    while(!cJSON_Compare(cjson_iter, cjson_fro, 1)) {
        cJSON_SetIntValue(cjson_iter->child, CHUNK_START(cjson_iter) + gap);
        cJSON_SetIntValue(cjson_iter->child->next, CHUNK_END(cjson_iter) + gap);
        cjson_iter = cjson_iter->next;
    }
    uint32_t fro_len;
    fro_len = CHUNK_END(cjson_fro) - CHUNK_START(cjson_fro);
    cJSON_SetIntValue(cjson_fro->child->next, aft_end);
    cJSON_SetIntValue(cjson_fro->child, aft_end - fro_len);

    free(buf);
    return new_buf;
}

static void delete_block(cJSON *cjson_head, uint32_t delete_from, uint32_t delete_len)
{
  cJSON *cjson_iter;
  cJSON *cjson_start;
  cJSON *cjson_end;
  cJSON *cjson_temp;
  cjson_iter = cjson_head->child;
  cjson_start = cjson_iter;
  while (cjson_iter != NULL && CHUNK_START(cjson_iter) < delete_from)
  {
    cjson_start = cjson_iter;
    cjson_iter = cjson_iter->next;
  }
  cjson_end = cjson_start;
  while (cjson_iter != NULL && CHUNK_START(cjson_iter) < delete_from + delete_len)
  {
    cjson_end = cjson_iter;
    cjson_iter = cjson_iter->next;
  }
  if (cJSON_Compare(cjson_start, cjson_end, 1))
  {
    cJSON_SetIntValue(cjson_start->child->next, CHUNK_END(cjson_start) - delete_len);
    cjson_iter = cjson_start->next;
    while (cjson_iter)
    {
      cJSON_SetIntValue(cjson_iter->child, CHUNK_START(cjson_iter) - delete_len);
      cJSON_SetIntValue(cjson_iter->child->next, CHUNK_END(cjson_iter) - delete_len);
      cjson_iter = cjson_iter->next;
    }
  }
  else
  {
    cjson_iter = cjson_start->next;
    while (!cJSON_Compare(cjson_iter, cjson_end, 1))
    {
      cjson_temp = cjson_iter->next;
      cJSON_DetachItemViaPointer(cjson_head, cjson_iter);
      cjson_iter = cjson_temp;
    }

    cJSON_DetachItemViaPointer(cjson_head, cjson_end);
    cJSON_SetIntValue(cjson_start->child->next, CHUNK_END(cjson_end) - delete_len);
    cjson_iter = cjson_start->next;
    while (cjson_iter)
    {
      cJSON_SetIntValue(cjson_iter->child, CHUNK_START(cjson_iter) - delete_len);
      cJSON_SetIntValue(cjson_iter->child->next, CHUNK_END(cjson_iter) - delete_len);
      cjson_iter = cjson_iter->next;
    }
    if (CHUNK_START(cjson_start) == CHUNK_END(cjson_start))
    {
      cJSON_DetachItemViaPointer(cjson_head, cjson_start);
    }
  }
}

void write_to_file(cJSON* cjson_head) {
    uint8_t *cjson_str = cJSON_Print(cjson_head);
    uint32_t fd;
    fd = open("temp.json", O_WRONLY | O_CREAT | O_TRUNC, 0600);
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
    len = 22;
    in_buf = calloc(0, len);
    // in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    read(fd, in_buf, len);
    cJSON *cjson_head, *cjson_temp;

    cjson_head = parse_json("input.txt.json");
    // cjson_temp = parse_json("input.txt.json");
    cjson_temp = cJSON_Duplicate(cjson_head, 1);

    // printf(cJSON_Print(cjson_temp));
    // printf("before insert: %d\n", cJSON_Compare(cjson_head->child, cjson_temp->child, 1));
    // printf(cJSON_Print(cjson_head->child));

    // in_buf = insert_chunk(in_buf, &len, cjson_head, 3, 4);
    // in_buf = delete_chunk(in_buf, cjson_head, 4);

    // printf("\n%d\n", cJSON_GetArraySize(cjson_head));

    in_buf = exchange_chunk(in_buf, len, cjson_head, 0, 3);
    printf(in_buf);
    printf("\nlen = %d\n", len);
    
    write_to_file(cjson_head);

    // printf("after insert: %d\n", cJSON_Compare(cjson_head->child, cjson_temp->child, 1));

    // cJSON *cjson_start, *cjson_end, *cjson_time, *cjson_iter;
    // cjson_start = cjson_temp->child;
    // cjson_end = cjson_start->next->next->next;
    // cjson_iter = cjson_start->next;
    // while (!cJSON_Compare(cjson_iter, cjson_end, 1))
    // {
    //     cjson_time = cjson_iter->next;
    //     cJSON_DetachItemViaPointer(cjson_temp, cjson_iter);
    //     cjson_iter = cjson_time;
    //     printf("lalal\n");
    // }
    // cJSON_DetachItemViaPointer(cjson_temp, cjson_end);
    // printf(cJSON_Print(cjson_temp));

    // delete_chunk(in_buf, cjson_head, 0);
    // write_to_file(cjson_head);
}