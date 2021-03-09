#include <ctype.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "chunk.h"
#include "hashMap.h"

#define CHUNK_START(chunk) ((cJSON *)chunk)->child->valueint
#define CHUNK_END(chunk) ((cJSON *)chunk)->child->next->valueint
#define CHUNK_ID_START(chunk) \
  ((cJSON *)chunk)->child->next->next->child->valueint
#define CHUNK_ID_END(chunk) \
  ((cJSON *)chunk)->child->next->next->child->next->valueint
#define MAX_LINE 8192

struct extra_data {
  uint8_t *data;    /* Dictionary token data            */
  uint32_t len;     /* Dictionary token length          */
  uint32_t hit_cnt; /* Use count in the corpus          */
};
typedef struct Node {
  uint32_t start;
  uint32_t end;
  struct Node *next;
} Node;

typedef struct Enum {
  uint8_t *id;
  struct Enum *next;
  uint32_t cans_num;
  uint8_t *candidates[];
} Enum;

typedef struct Length {
  uint8_t *id1;
  uint8_t *id2;
  struct Length *next;
} Length;

typedef struct Offset {
  uint8_t abs;  // 1 or 0
  uint8_t *id1;
  uint8_t *id2;
  struct Offset *next;
} Offset;

typedef struct Constraint {
  uint8_t *id1;
  uint8_t *id2;
  uint32_t type;
  struct Constraint *next;
} Constraint;

typedef struct Track {
  struct Enum *enums;
  struct Length *lengths;
  struct Offset *offsets;
  struct Constraint *constraints;
} Track;

typedef enum { INSERT, DELETE, CHANGE, EXCHANGE } MUTATION_OP;

struct mutation_log_struct {
  uint8_t *source;
  uint8_t *result;
  MUTATION_OP operation;
  uint32_t source_start;
  uint32_t source_end;
  uint32_t dest_start;
  uint32_t dest_end;
  uint32_t origin;
  uint32_t after;
  uint32_t length;
  struct mutation_log_struct *next;
};

int32_t get_json_start(const cJSON *chunk) {
  if (cJSON_HasObjectItem(chunk, "start")) {
    return cJSON_GetObjectItemCaseSensitive(chunk, "start")->valueint;
  }
  return -1;
}

int32_t get_json_end(const cJSON *chunk) {
  if (cJSON_HasObjectItem(chunk, "end")) {
    return cJSON_GetObjectItemCaseSensitive(chunk, "end")->valueint;
  }
  return -1;
}

uint8_t *get_json_type(const cJSON *chunk) {
  if (cJSON_HasObjectItem(chunk, "type")) {
    return cJSON_GetObjectItemCaseSensitive(chunk, "type")->valuestring;
  }
  return NULL;
}

uint32_t get_chunk_abs_start(const Chunk *chunk) {
  uint32_t start = chunk->start;
  const Chunk *father;
  father = chunk->father;
  while (father) {
    start += father->start;
    father = father->father;
  }
  return start;
}

uint32_t get_chunk_abs_end(const Chunk *chunk) {
  uint32_t end = chunk->end;
  const Chunk *father;
  father = chunk->father;
  while (father) {
    end += father->start;
    father = father->father;
  }
  return end;
}

static struct mutation_log_struct *mutation_log;

void mutation_enum(uint8_t *out_buf, Enum *enum_chunk, HashMap map) {
  Chunk *chunk = map->get(map, enum_chunk->id);
  if (chunk == NULL) {
    return;
  }
  int32_t chunk_start = chunk->start;
  int32_t chunk_end = chunk->end;
  if (chunk_start < 0 || chunk_end < 0) {
    return;
  }
  printf("mutation enum, start = %d, end = %d\n", chunk_start, chunk_end);
  for (uint32_t i = 0; i < enum_chunk->cans_num; i++) {
    ;
  }
}

void mutation_length(uint8_t *out_buf, cJSON *chunk) {
  int32_t chunk_start = get_json_start(chunk);
  int32_t chunk_end = get_json_end(chunk);
  if (chunk_start < 0 || chunk_end < 0) {
    return;
  }
  cJSON *constraint = cJSON_GetObjectItemCaseSensitive(chunk, "constraint");
  if (!constraint) {
    printf("mutation length without constraint, start = %d, end = %d\n",
           chunk_start, chunk_end);
  } else {
    uint32_t k = cJSON_GetObjectItemCaseSensitive(constraint, "k")->valueint;
    uint32_t b = cJSON_GetObjectItemCaseSensitive(constraint, "b")->valueint;
    uint8_t *operand =
        cJSON_GetObjectItemCaseSensitive(constraint, "operand")->valuestring;
    uint8_t *type =
        cJSON_GetObjectItemCaseSensitive(constraint, "type")->valuestring;
    if (strcmp(type, "length") == 0) {
      printf(
          "mutation length with constraint type length, start = %d, end = %d\n",
          chunk_start, chunk_end);
    }
    if (strcmp(type, "value") == 0) {
      printf(
          "mutation length with constraint type value, start = %d, end = %d\n",
          chunk_start, chunk_end);
    }
  }
}

void mutation_offset(uint8_t *out_buf, cJSON *chunk) {
  int32_t chunk_start = get_json_start(chunk);
  int32_t chunk_end = get_json_end(chunk);
  if (chunk_start < 0 || chunk_end < 0) {
    return;
  }
  printf("mutation offset, start = %d, end = %d\n", chunk_start, chunk_end);
}

void mutation_other(uint8_t *out_buf, cJSON *chunk) {
  int32_t chunk_start = get_json_start(chunk);
  int32_t chunk_end = get_json_end(chunk);
  if (chunk_start < 0 || chunk_end < 0) {
    return;
  }
  printf("mutation other , start = %d, end = %d\n", chunk_start, chunk_end);
}

void mutation_checkNum(uint8_t *out_buf, cJSON *chunk) {
  int32_t chunk_start = get_json_start(chunk);
  int32_t chunk_end = get_json_end(chunk);
  if (chunk_start < 0 || chunk_end < 0) {
    return;
  }
  printf("mutation checkNum, start = %d, end = %d\n", chunk_start, chunk_end);
}

void struct_aware_mutation(uint32_t *len, const uint8_t *in_buf,
                           uint8_t *out_buf, cJSON *cjson_head) {
  uint32_t chunk_num = cJSON_GetArraySize(cjson_head);
  printf("chunk_num = %d\n", chunk_num);
  for (uint32_t i = 0; i < chunk_num; i++) {
    cJSON *chunk = cJSON_GetArrayItem(cjson_head, i);
    uint32_t field_num;
    if (!chunk) {
      continue;
    }
    uint8_t *type = get_json_type(chunk);
    if (!type) {
      continue;
    }
    void (*mutation_fuc)(uint8_t * out_buf, cJSON * chunk);
    if (strcmp(type, "Enum") == 0) {
      // mutation_fuc = mutation_enum;
    }
    if (strcmp(type, "Length") == 0) {
      mutation_fuc = mutation_length;
    }
    if (strcmp(type, "Offset") == 0) {
      mutation_fuc = mutation_offset;
    }
    if (strcmp(type, "Checksum") == 0) {
      mutation_fuc = mutation_checkNum;
    }
    if (strcmp(type, "Other") == 0) {
      mutation_fuc = mutation_other;
    }
    if (mutation_fuc) {
      mutation_fuc(out_buf, chunk);
      memcpy(out_buf, in_buf, *len);
    }
    struct_aware_mutation(len, in_buf, out_buf, chunk);
    if (cJSON_HasObjectItem(chunk, "son")) {
      struct_aware_mutation(len, in_buf, out_buf,
                            cJSON_GetObjectItemCaseSensitive(chunk, "son"));
    }
  }
}

Node *get_node_list(Chunk *tree) {
  Chunk *iter;
  Node *head, *top;
  head = top = NULL;
  iter = tree;
  while (iter) {
    if (iter->son == NULL) {
      Node *node = calloc(sizeof(Node), sizeof(char));
      node->start = get_chunk_abs_start(iter);
      node->end = get_chunk_abs_end(iter);
      if (top) {
        top->next = node;
        top = node;
      } else {
        head = top = node;
      }
    } else {
      if (top) {
        top->next = get_node_list(iter->son);
      } else {
        head = top = get_node_list(iter->son);
      }
      while (top->next) {
        top = top->next;
      }
    }
    iter = iter->next;
  }
  return head;
}

void free_node_list(Node *head) {
  Node *item = NULL;
  while (head) {
    item = head->next;
    free(head);
    head = item;
  }
}

void generate_id(char *random_str) {
  int i, random_num, seed_str_len, len;
  struct timeval tv;
  unsigned int seed_num;
  char seed_str[] =
      "abcdefghijklmnopqrstuvwxyz"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

  seed_str_len = strlen(seed_str);

  gettimeofday(&tv, NULL);
  seed_num = (unsigned int)(tv.tv_sec + tv.tv_usec);
  srand(seed_num);

  len = strlen(random_str);
  for (i = 0; i < len; i++) {
    random_num = rand() % seed_str_len;
    random_str[i] = seed_str[random_num];
  }
}

Chunk *json_to_tree(cJSON *cjson_head) {
  uint32_t chunk_num = cJSON_GetArraySize(cjson_head);
  Chunk *head, *top, *iter;
  head = top = NULL;
  for (uint32_t i = 0; i < chunk_num; i++) {
    cJSON *chunk = cJSON_GetArrayItem(cjson_head, i);
    if (!chunk) {
      continue;
    }
    int32_t start = get_json_start(chunk);
    int32_t end = get_json_end(chunk);
    if (start < 0 || end < 0) {
      continue;
    }
    Chunk *node = calloc(sizeof(Chunk), sizeof(char));
    node->start = start;
    node->end = end;
    node->id = (uint8_t *)malloc(strlen(chunk->string) + 1);
    strcpy(node->id, chunk->string);
    node->father = node->son = node->prev = node->next = NULL;
    node->cons = NULL;
    if (top) {
      top->next = node;
      node->prev = top;
      top = node;
    } else {
      head = top = node;
    }
    if (cJSON_HasObjectItem(chunk, "son")) {
      top->son = json_to_tree(cJSON_GetObjectItemCaseSensitive(chunk, "son"));
      iter = top->son;
      while (iter) {
        iter->father = top;
        iter = iter->next;
      }
    }
  }
  return head;
}

Chunk *get_tree(cJSON *cjson_head) {
  Chunk *head, *root, *iter;
  uint32_t end;
  head = json_to_tree(cjson_head);
  if (head->next) {
    root = malloc(sizeof(Chunk));
    root->son = head;
    root->start = head->start;
    iter = head;
    while (iter) {
      iter->father = root;
      end = iter->end;
      iter = iter->next;
    }
    root->end = end;
    root->id = "root";
  } else {
    root = head;
  }
  return root;
}

cJSON *tree_to_json(Chunk *chunk_head) {
  Chunk *iter;
  iter = chunk_head;
  cJSON *json_head;
  json_head = cJSON_CreateObject();
  while (iter) {
    cJSON *cjson = cJSON_CreateObject();
    cJSON_AddNumberToObject(cjson, "start", iter->start);
    cJSON_AddNumberToObject(cjson, "end", iter->end);
    if (iter->son) {
      cJSON_AddItemToObject(cjson, "son", tree_to_json(iter->son));
    }
    cJSON_AddItemToObject(json_head, iter->id, cjson);
    iter = iter->next;
  }
  return json_head;
}

void tree_add_map(Chunk *head, HashMap map) {
  Chunk *iter = head;
  while (iter) {
    map->put(map, iter->id, iter);
    if (iter->son) {
      tree_add_map(iter->son, map);
    }
    iter = iter->next;
  }
}

void free_tree(Chunk *head, Boolean recurse) {
  Chunk *iter = NULL;
  while (head) {
    if (recurse) {
      iter = head->next;
    } else {
      iter = NULL;
    }
    free(head->id);
    head->id = NULL;
    if (head->son) {
      free_tree(head->son, True);
    }
    free(head);
    head = iter;
  }
}

void print_tree(Chunk *head) {
  Chunk *iter = head;
  while (iter) {
    printf("Name = %s, start = %d, end = %d", iter->id, iter->start, iter->end);
    if (iter->father) {
      printf("father Name = %s\n", iter->father->id);
    } else {
      printf("no father\n");
    }
    if (iter->prev) {
      printf("Prev Name = %s\n", iter->prev->id);
    }
    if (iter->son) {
      print_tree(iter->son);
    }
    iter = iter->next;
  }
}

Track *parse_track_file(uint8_t *path) {
  FILE *fp;
  uint8_t buffer[1024];
  uint8_t *delim, *id1, *id2, *type;
  uint32_t num, i;
  Track *track;
  Enum *enum_top = NULL;
  Offset *offset_top = NULL;
  Length *length_top = NULL;
  Constraint *cons_top = NULL;
  track = calloc(sizeof(struct Track), sizeof(char));
  delim = "(),{} ";
  if ((fp = fopen(path, "r")) == NULL) {
    printf("open file error\n");
    exit(EXIT_FAILURE);
  }
  while (!feof(fp)) {
    fgets(buffer, 1024, fp);
    id1 = strtok(buffer, delim);
    id2 = strtok(NULL, delim);
    type = strtok(NULL, delim);
    if (strcmp(type, "Enum") == 0) {
      uint8_t *candidate;
      num = atoi(strtok(NULL, delim));
      Enum *enum_chunk = malloc(sizeof(struct Enum) + num * sizeof(uint8_t *));
      enum_chunk->id = (uint8_t *)malloc(strlen(id1) + 1);
      strcpy(enum_chunk->id, id1);
      enum_chunk->cans_num = num;
      for (i = 0; i < num; i++) {
        candidate = strtok(NULL, delim);
        enum_chunk->candidates[i] = malloc(sizeof(candidate) + 1);
        strcpy(enum_chunk->candidates[i], candidate);
      }
      if (enum_top) {
        enum_top->next = enum_chunk;
        enum_top = enum_chunk;
      } else {
        track->enums = enum_top = enum_chunk;
      }
    } else if (strcmp(type, "Length") == 0) {
      num = atoi(strtok(NULL, delim));
      Length *len_chunk = malloc(sizeof(struct Length));
      len_chunk->id1 = (uint8_t *)malloc(strlen(id1) + 1);
      len_chunk->id2 = (uint8_t *)malloc(strlen(id2) + 1);
      strcpy(len_chunk->id1, id1);
      strcpy(len_chunk->id2, id2);
      if (length_top) {
        length_top->next = len_chunk;
        length_top = len_chunk;
      } else {
        track->lengths = length_top = len_chunk;
      }
    } else if (strcmp(type, "Offset") == 0) {
      Offset *offset_chunk = malloc(sizeof(struct Offset));
      num = atoi(strtok(NULL, delim));
      offset_chunk->id1 = (uint8_t *)malloc(strlen(id1) + 1);
      strcpy(offset_chunk->id1, id1);
      offset_chunk->id2 = (uint8_t *)malloc(strlen(id2) + 1);
      strcpy(offset_chunk->id2, id2);
      offset_chunk->abs = num;
      if (offset_top) {
        offset_top->next = offset_chunk;
        offset_top = offset_chunk;
      } else {
        track->offsets = offset_top = offset_chunk;
      }
    } else if (strcmp(type, "Constraint") == 0) {
      Constraint *cons_chunk = malloc(sizeof(struct Constraint));
      num = atoi(strtok(NULL, delim));
      cons_chunk->id1 = (uint8_t *)malloc(strlen(id1) + 1);
      cons_chunk->id2 = (uint8_t *)malloc(strlen(id2) + 1);
      strcpy(cons_chunk->id1, id1);
      strcpy(cons_chunk->id2, id2);
      cons_chunk->type = num;
      if (cons_top) {
        cons_top->next = cons_chunk;
        cons_top = cons_chunk;
      } else {
        cons_top = track->constraints = cons_chunk;
      }
    }
  }
  fclose(fp);
  cons_top->next = NULL;
  offset_top->next = NULL;
  length_top->next = NULL;
  enum_top->next = NULL;
  return track;
}

void print_track(Track *track) {
  Enum *enum_top = track->enums;
  Constraint *cons_top = track->constraints;
  Length *len_top = track->lengths;
  Offset *offset_top = track->offsets;

  printf("enum\n");
  while (enum_top) {
    printf("id = %s ", enum_top->id);
    printf("candidate = %s ", enum_top->candidates[0]);
    printf("candidate = %s ", enum_top->candidates[1]);
    printf("candidate = %s\n", enum_top->candidates[2]);
    enum_top = enum_top->next;
  }
  printf("constraint\n");
  while (cons_top) {
    printf("id1 = %s ", cons_top->id1);
    printf("id2 = %s ", cons_top->id2);
    printf("num = %d\n", cons_top->type);
    cons_top = cons_top->next;
  }
  printf("length\n");
  while (len_top) {
    printf("id1 = %s ", len_top->id1);
    printf("id2 = %s\n", len_top->id2);
    len_top = len_top->next;
  }
  printf("offset\n");
  while (offset_top) {
    printf("id1 = %s ", offset_top->id1);
    printf("id2 = %s ", offset_top->id2);
    printf("abs = %d\n", offset_top->abs);
    offset_top = offset_top->next;
  }
}

void free_enum(Enum *node) {
  free(node->id);
  uint32_t i;
  for (i = 0; i < node->cans_num; i++) {
    free(node->candidates[i]);
  }
  free(node);
}

void free_length(Length *node) {
  free(node->id1);
  free(node->id2);
  free(node);
}

void free_offset(Offset *node) {
  free(node->id1);
  free(node->id2);
  free(node);
}

void free_constraint(Constraint *node) {
  free(node->id1);
  free(node->id2);
  free(node);
}

void free_track(Track *track) {
  Enum *enum_next = NULL;
  Constraint *cons_next = NULL;
  Length *len_next = NULL;
  Offset *offset_next = NULL;

  printf("free offsets\n");
  while (track->offsets) {
    offset_next = track->offsets->next;
    free_offset(track->offsets);
    track->offsets = offset_next;
  }
  printf("free enums\n");
  while (track->enums) {
    enum_next = track->enums->next;
    free_enum(track->enums);
    track->enums = enum_next;
  }

  printf("free constraints\n");
  while (track->constraints) {
    cons_next = track->constraints->next;
    free_constraint(track->constraints);
    track->constraints = cons_next;
  }
  printf("free lengths\n");
  while (track->lengths) {
    len_next = track->lengths->next;
    free_length(track->lengths);
    track->lengths = len_next;
  }
  free(track);
}

struct Node *merge(struct Node *head1, struct Node *head2) {
  struct Node *dummyHead = malloc(sizeof(struct Node));
  dummyHead->start = 0;
  struct Node *temp = dummyHead, *temp1 = head1, *temp2 = head2;
  while (temp1 != NULL && temp2 != NULL) {
    if (temp1->start < temp2->start) {
      temp->next = temp1;
      temp1 = temp1->next;
    } else if (temp1->start == temp2->start) {
      if (temp1->end < temp2->end) {
        temp->next = temp1;
        temp1 = temp1->next;
      } else {
        temp->next = temp2;
        temp2 = temp2->next;
      }
    } else {
      temp->next = temp2;
      temp2 = temp2->next;
    }
    temp = temp->next;
  }
  if (temp1 != NULL) {
    temp->next = temp1;
  } else if (temp2 != NULL) {
    temp->next = temp2;
  }
  temp = dummyHead->next;
  free(dummyHead);
  return temp;
}

struct Node *toSortList(struct Node *head, struct Node *tail) {
  if (head == NULL) {
    return head;
  }
  if (head->next == tail) {
    head->next = NULL;
    return head;
  }
  struct Node *slow = head, *fast = head;
  while (fast != tail) {
    slow = slow->next;
    fast = fast->next;
    if (fast != tail) {
      fast = fast->next;
    }
  }
  struct Node *mid = slow;
  return merge(toSortList(head, mid), toSortList(mid, tail));
}

Node *sortList(Node *list) { return toSortList(list, NULL); }

void new_mutation_log_file() {
  uint32_t fd;
  fd = open("temp.json", O_WRONLY | O_CREAT | O_TRUNC, 0600);
  struct mutation_log_struct *log_current;
  log_current = mutation_log;
  while (log_current) {
    switch (log_current->operation) {
      case INSERT:
        /* code */
        break;
      case DELETE:
        /* code */
        break;
      case CHANGE:
        /* code */
        break;
      case EXCHANGE:
        /* code */
        break;
      default:
        break;
    }
    log_current = log_current->next;
  }
  close(fd);
}

const cJSON *get_chunk_constraint(const cJSON *chunk) {
  if (cJSON_HasObjectItem(chunk, "constraint")) {
    return cJSON_GetObjectItemCaseSensitive(chunk, "constraint");
  }
  return NULL;
}

cJSON *parse_json(const uint8_t *format_file) {
  cJSON *cjson_head;
  int32_t fd;
  uint8_t *in_buf;
  struct stat st;
  int32_t n;
  if (lstat(format_file, &st)) {
    printf("lstat error\n");
    exit(0);
  }
  fd = open(format_file, O_RDONLY);
  in_buf = calloc(st.st_size, sizeof(char));
  n = read(fd, in_buf, st.st_size);
  cjson_head = cJSON_ParseWithLength(in_buf, st.st_size);
  if (cjson_head == NULL) {
    printf("parse fail\n");
    return NULL;
  }
  close(fd);
  free(in_buf);
  return cjson_head;
}

Chunk *find_chunk(uint8_t *id, Chunk *head) {
  Chunk *iter, *result;
  iter = head;
  while (iter) {
    if (strcmp(id, iter->id) == 0) {
      return iter;
    }
    if (iter->son) {
      result = find_chunk(id, iter->son);
      if (result) {
        return result;
      }
    }
    iter = iter->next;
  }
  return NULL;
}

uint8_t is_inner_chunk(Chunk *father, Chunk *son) {
  Chunk *iter;
  iter = son->father;
  while (iter) {
    if (strcmp(father->id, iter->id) == 0) {
      return 1;
    }
    iter = iter->father;
  }
  return 0;
}

void chunk_add_len(Chunk *head, int32_t len) {
  Chunk *iter = head;
  while (iter) {
    iter->start += len;
    iter->end += len;
    iter = iter->next;
  }
}

Chunk *chunk_duplicate(Chunk *head, Boolean recurse) {
  Chunk *dup_head, *top, *iter, *temp;
  dup_head = top = temp = NULL;
  iter = head;
  while (iter) {
    Chunk *node = calloc(sizeof(Chunk), sizeof(char));
    node->start = iter->start;
    node->end = iter->end;
    node->id = (uint8_t *)malloc(strlen(iter->id) + 1);
    strcpy(node->id, iter->id);
    node->son = NULL;
    node->next = NULL;
    node->prev = NULL;
    node->father = NULL;
    if (top) {
      top->next = node;
      node->prev = top;
      top = node;
    } else {
      dup_head = top = node;
    }
    if (iter->son) {
      top->son = chunk_duplicate(iter->son, True);
      temp = top->son;
      while (temp) {
        temp->father = top;
        temp = temp->next;
      }
    }
    if (recurse) {
      iter = iter->next;
    } else {
      iter = NULL;
    }
  }
  return dup_head;
}

void chunk_detach(Chunk *head, Chunk *item) {
  Chunk *father;
  father = item->father;
  uint32_t delete_len = item->end - item->start;
  while (father) {
    father->end -= delete_len;
    if (father->next) {
      chunk_add_len(father->next, -delete_len);
    }
    father = father->father;
  }
  if (item->next) {
    chunk_add_len(item->next, -delete_len);
  }
  if (item->prev) {
    if (item->next) {
      item->prev->next = item->next;
      item->next->prev = item->prev;
    } else {
      item->prev->next = NULL;
    }
  } else if (item->father) {
    if (item->next) {
      item->father->son = item->next;
      item->next->prev = NULL;
    } else {
      item->father->son = NULL;
    }
  }
}

void chunk_insert(Chunk *item, Chunk *insert) {
  uint32_t len;
  len = insert->end - insert->start;
  chunk_add_len(insert, item->end - insert->start);
  Chunk *father = item->father;
  while (father) {
    father->end += len;
    if (father->next) {
      chunk_add_len(father->next, len);
    }
    father = father->father;
  }
  printf("father add over\n");
  if (item->next) {
    chunk_add_len(item->next, len);
  }
  printf("next add over\n");
  if (item->next) {
    item->next->prev = insert;
    insert->next = item->next;
  } else {
    insert->next = NULL;
  }
  item->next = insert;
  insert->prev = item;

  insert->father = item->father;
  printf("adjust over\n");
}

uint8_t *copy_and_insert(uint8_t *buf, uint32_t *len, uint32_t insert_at,
                         uint32_t copy_start, uint32_t copy_len) {
  uint8_t *new_buf;
  new_buf = malloc(*len + copy_len);

  memcpy(new_buf, buf, insert_at);
  memcpy(new_buf + insert_at, buf + copy_start, copy_len);
  memcpy(new_buf + insert_at + copy_len, buf + insert_at, *len - insert_at);

  *len += copy_len;
  free(buf);
  return new_buf;
}

void set_id_add_map(Chunk *head, HashMap map) {
  Chunk *iter = head;
  while (iter) {
    while (map->exists(map, iter->id)) {
      generate_id(iter->id);
    }
    map->put(map, iter->id, iter);
    if (iter->son) {
      set_id_add_map(iter->son, map);
    }
    iter = iter->next;
  }
}

void delete_from_map(Chunk *head, HashMap map) {
  Chunk *iter = head;
  while (iter) {
    map->remove(map, iter->id);
    if (iter->son) {
      delete_from_map(iter->son, map);
    }
    iter = iter->next;
  }
}

uint8_t *insert_chunk(uint8_t *buf, uint32_t *len, HashMap map, Chunk *head,
                      uint8_t *chunk_id, uint8_t *insert_id, Boolean after) {
  uint32_t clone_len;
  uint8_t *new_buf;
  Chunk *chunk_choose = find_chunk(chunk_id, head);
  Chunk *item = find_chunk(insert_id, head);
  Boolean has_prev = True;
  Chunk *temp;
  temp = NULL;
  if (item == NULL || chunk_choose == NULL) {
    return buf;
  }
  clone_len = chunk_choose->end - chunk_choose->start;
  if (clone_len == 0) {
    return buf;
  }
  printf("insert id = %s, chunk id = %s\n", insert_id, chunk_id);
  Chunk *chunk_dup = chunk_duplicate(chunk_choose, False);
  if (!after) {
    if (item->prev) {
      item = item->prev;
    } else {
      has_prev = False;
      temp = malloc(sizeof(Chunk));
      temp->start = item->start;
      temp->end = item->start;
      temp->prev = NULL;
      temp->father = item->father;
      temp->next = item;
      item->prev = temp;
      temp->son = NULL;
      if (temp->father) {
        temp->father->son = temp;
      }
      item = temp;
    }
  }
  new_buf = copy_and_insert(buf, len, get_chunk_abs_end(item),
                            get_chunk_abs_start(chunk_choose), clone_len);
  set_id_add_map(chunk_dup, map);
  chunk_insert(item, chunk_dup);
  if (temp != NULL) {
    if (temp->father) {
      temp->father->son = temp->next;
      temp->next->prev = NULL;
      free(temp);
    }
  }
  return new_buf;
}

uint8_t *delete_data(uint8_t *buf, uint32_t *len, uint32_t delete_start,
                     uint32_t delete_len) {
  uint8_t *new_buf;
  new_buf = malloc(*len - delete_len);
  memcpy(new_buf, buf, delete_start);
  memcpy(new_buf + delete_start, buf + delete_start + delete_len,
         *len - delete_start - delete_len);
  *len -= delete_len;
  free(buf);
  return new_buf;
}

uint8_t *delete_chunk(uint8_t *buf, uint32_t *len, HashMap map, Chunk *head,
                      uint8_t *id) {
  Chunk *chunk_delete = find_chunk(id, head);
  if (chunk_delete == NULL) {
    return buf;
  }
  uint32_t delete_start = get_chunk_abs_start(chunk_delete);
  uint32_t delete_len = chunk_delete->end - chunk_delete->start;
  if (delete_len >= *len) {
    return buf;
  }
  chunk_detach(head, chunk_delete);
  delete_from_map(chunk_delete, map);
  free_tree(chunk_delete, False);
  return delete_data(buf, len, delete_start, delete_len);
}

Chunk *swap_chunks(Chunk *head, Chunk *left, Chunk *right) {
  Chunk *temp;
  if (right->next == NULL) {
    if (left->next == right) {
      right->next = left;
      right->prev = left->prev;
      left->next = NULL;
      if (left->prev != NULL) {
        left->prev->next = right;
      }
      left->prev = right;
    } else {
      right->next = left->next;
      right->prev->next = left;
      temp = right->prev;
      right->prev = left->prev;
      left->next->prev = right;
      left->next = NULL;
      if (left->prev != NULL) {
        left->prev->next = right;
      }
      left->prev = temp;
    }
  } else {
    if (left->next == right) {
      right->next->prev = left;
      temp = right->next;
      right->next = left;
      right->prev = left->prev;
      left->next = temp;
      if (left->prev != NULL) {
        left->prev->next = right;
      }
      left->prev = right;
    } else {
      right->next->prev = left;
      temp = right->next;
      right->next = left->next;
      left->next->prev = right;
      left->next = temp;
      right->prev->next = left;
      temp = right->prev;
      right->prev = left->prev;
      if (left->prev != NULL) {
        left->prev->next = right;
      }
      left->prev = temp;
    }
  }
  if (right->prev == NULL) {
    head = right;
  }
  return head;
}

void print_swap_chunks(Chunk *head) {
  Chunk *iter = head;
  while (iter) {
    printf("id = %s, ", iter->id);
    if (iter->prev) {
      printf("prev->id = %s, ", iter->prev->id);
    }
    if (iter->next) {
      printf("next->id = %s, ", iter->next->id);
    }
    printf("\n");
    iter = iter->next;
  }
}

void test_swap_chunks() {
  Chunk *head, *chunk, *chunk1, *chunk2, *chunk3;
  head = malloc(sizeof(Chunk));
  head->id = "head";
  chunk = malloc(sizeof(Chunk));
  chunk->id = "chunk";
  chunk1 = malloc(sizeof(Chunk));
  chunk1->id = "chunk1";
  chunk2 = malloc(sizeof(Chunk));
  chunk2->id = "chunk2";
  chunk3 = malloc(sizeof(Chunk));
  chunk3->id = "chunk3";

  head->next = chunk;
  head->prev = NULL;
  chunk->prev = head;
  chunk->next = chunk1;
  chunk1->prev = chunk;
  chunk1->next = chunk2;
  chunk2->prev = chunk1;
  chunk2->next = chunk3;
  chunk3->prev = chunk2;
  chunk3->next = NULL;

  printf("orign\n");
  print_swap_chunks(head);

  // printf("swap chunk1  and chunk3\n");
  // swap_chunks(head, chunk1, chunk3);
  // print_swap_chunks(head);
  // swap_chunks(head, chunk3, chunk1);

  // printf("swap chunk1  and chunk2\n");
  // swap_chunks(head, chunk1, chunk2);
  // print_swap_chunks(head);
  // swap_chunks(head, chunk2, chunk1);

  // printf("swap chunk2  and chunk3\n");
  // swap_chunks(head, chunk2, chunk3);
  // print_swap_chunks(head);
  // swap_chunks(head, chunk3, chunk2);

  printf("swap chunk and chunk1\n");
  head = swap_chunks(head, chunk2, chunk3);
  print_swap_chunks(head);
  // swap_chunks(head, chunk1, head);
}

uint32_t random_num(uint32_t rand_max) {
  struct timeval tv;
  unsigned int seed_num;

  gettimeofday(&tv, NULL);
  seed_num = (unsigned int)(tv.tv_sec + tv.tv_usec);
  srand(seed_num);
  return rand() % rand_max;
}

Chunk *random_chunk(Chunk *head) {
  Chunk *reserve, *iter;
  uint32_t count, rand;
  iter = head;
  count = 0;
  while (iter) {
    count += 1;
    rand = random_num(count) + 1;
    if (rand == count) {
      reserve = iter;
    }
    iter = iter->next;
  }
  return reserve;
}

uint8_t *exchange_chunk(uint8_t *buf, uint32_t len, Chunk *head, uint8_t *id1) {
  Chunk *chunk_left, *chunk_right, *temp;
  uint32_t left_start, left_end, left_len, right_start, right_end, right_len;
  uint32_t gap;
  uint8_t *new_buf;
  chunk_left = find_chunk(id1, head);
  if (chunk_left == NULL) {
    return buf;
  }
  chunk_left = random_chunk(chunk_left->father->son);
  chunk_right = random_chunk(chunk_left->father->son);
  if (strcmp(chunk_left->id, chunk_right->id) == 0) {
    return buf;
  }
  if (get_chunk_abs_start(chunk_left) > get_chunk_abs_start(chunk_right)) {
    temp = chunk_left;
    chunk_left = chunk_right;
    chunk_right = temp;
  }
  left_start = get_chunk_abs_start(chunk_left);
  left_end = get_chunk_abs_end(chunk_left);
  right_start = get_chunk_abs_start(chunk_right);
  right_end = get_chunk_abs_end(chunk_right);
  new_buf = malloc(len);
  memcpy(new_buf, buf, left_start);
  memcpy(new_buf + left_start, buf + right_start, right_end - right_start);
  memcpy(new_buf + left_start + right_end - right_start, buf + left_end,
         right_start - left_end);
  memcpy(new_buf + left_start + right_end - left_end, buf + left_start,
         left_end - left_start);
  memcpy(new_buf + right_end, buf + right_end, len - right_end);
  free(buf);

  left_len = chunk_left->end - chunk_left->start;
  right_len = chunk_right->end - chunk_right->start;
  gap = right_len - left_len;

  chunk_left->end = chunk_right->end;
  chunk_right->end = chunk_left->start + right_len;
  chunk_right->start = chunk_left->start;
  chunk_left->start = chunk_left->end - left_len;

  temp = chunk_left->next;
  while (strcmp(temp->id, chunk_right->id) != 0) {
    temp->start += gap;
    temp->end += gap;
    temp = temp->next;
  }
  chunk_left->father->son =
      swap_chunks(chunk_left->father->son, chunk_left, chunk_right);
  return new_buf;
}

void write_to_file(cJSON *cjson_head) {
  uint8_t *cjson_str = cJSON_Print(cjson_head);
  uint32_t fd;
  fd = open("temp.json", O_WRONLY | O_CREAT | O_TRUNC, 0600);
  write(fd, cjson_str, strlen(cjson_str));
  close(fd);
  free(cjson_str);
}

void number_add(uint8_t *buf, Chunk *chunk, int32_t num) {
  uint32_t chunk_start, chunk_len;
  chunk_start = get_chunk_abs_start(chunk);
  chunk_len = chunk->end - chunk->start;
  if (chunk_len == 1) {
    *(uint8_t *)(buf + chunk_start) += num;
  } else if (chunk_len == 2) {
    *(uint16_t *)(buf + chunk_start) += num;
  } else if (chunk_len == 4) {
    *(uint32_t *)(buf + chunk_start) += num;
  }
}

Chunk *find_chunk_include(Chunk *head, uint32_t num) {
  Chunk *iter;
  iter = head;
  while (iter) {
    if (get_chunk_abs_end(iter) <= num) {
      iter = iter->next;
    } else if (get_chunk_abs_start(iter) > num) {
      return NULL;
    } else if (iter->son) {
      return find_chunk_include(iter->son, num);
    } else {
      return iter;
    }
  }
  return NULL;
}

void insert_block(Chunk *head, uint32_t insert_to, uint32_t insert_len) {
  Chunk *item = find_chunk_include(head, insert_to);
  if (item == NULL) {
    return;
  }
  Chunk *father = item->father;
  while (father) {
    father->end += insert_len;
    if (father->next) {
      chunk_add_len(father->next, insert_len);
    }
    father = father->father;
  }
  if (item->next) {
    chunk_add_len(item->next, insert_len);
  }
}

Chunk *splice_tree(Chunk *head1, Chunk *head2, uint32_t split_at) {
  Chunk *item1 = find_chunk_include(head1, split_at);
  Chunk *item2 = find_chunk_include(head2, split_at);
  Chunk *item1_root = item1;
  Chunk *item2_root = item2;
  Chunk *prev, *iter, *root;
  while (item1_root->father) {
    free_tree(item1_root->next, True);
    item1_root->next = NULL;
    item1_root->end =
        split_at - get_chunk_abs_start(item1_root) + item1_root->start;
    item1_root = item1_root->father;
  }
  item1_root->end =
      split_at - get_chunk_abs_start(item1_root) + item1_root->start;
  
  while (item2_root->father) {
    prev = item2_root->prev;
    while (prev) {
      iter = prev->prev;
      free_tree(prev, False);
      prev = iter;
    }
    item2_root->father->son = item2_root;
    item2_root->prev = NULL;
    item2_root->end = get_chunk_abs_end(item2_root) - split_at;
    item2_root->start = 0;
    chunk_add_len(item2_root->next, get_chunk_abs_start(item2_root) - split_at);
    item2_root = item2_root->father;
  }
  item2_root->end = item2_root->end - split_at;
  item2_root->start = 0;
  chunk_add_len(item2_root, item1_root->end);
  HashMap map = createHashMap(NULL, NULL);
  tree_add_map(item1_root, map);
  root = malloc(sizeof(Chunk));
  item1_root->next = item2_root;
  item2_root->prev = item1_root;
  root->son = item1_root;
  root->father = root->next = NULL;
  root->start = 0;
  root->end = item2_root->end;
  root->id = NULL;
  set_id_add_map(item2_root, map);
  map->clear(map);
  free(map);
  return root;
}

void struct_havoc_stage(uint8_t *buf, uint32_t len, cJSON *json) {
  uint8_t **all_chunks;
  uint32_t chunk_num = 0, out_len;
  uint32_t stage_max, stage_cur, i, index1, index2;
  uint8_t *out_buf;
  Chunk *tree, *out_tree;
  tree = get_tree(json);
  out_len = len;
  out_buf = malloc(len);
  memcpy(out_buf, buf, len);
  out_tree = chunk_duplicate(tree, True);
  HashMap map = createHashMap(NULL, NULL);
  tree_add_map(tree->son, map);
  all_chunks = malloc(map->size * sizeof(uint8_t *));
  HashMapIterator map_iter = createHashMapIterator(map);
  while (hasNextHashMapIterator(map_iter)) {
    map_iter = nextHashMapIterator(map_iter);
    all_chunks[chunk_num] = map_iter->entry->key;
    chunk_num++;
  }
  map->clear(map);
  free(map);
  map = createHashMap(NULL, NULL);
  tree_add_map(out_tree->son, map);
  stage_max = chunk_num * chunk_num;
  stage_cur = 0;
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    for (i = 0; i < 3; i++) {
      uint32_t num = random_num(3);
      switch (num) {
        case 0: {
          printf("insert chunk\n");
          index1 = random_num(chunk_num);
          index2 = random_num(chunk_num);
          out_buf =
              insert_chunk(out_buf, &out_len, map, out_tree, all_chunks[index1],
                           all_chunks[index2], random_num(2));
          break;
        };
        case 1: {
          printf("delete chunk\n");
          index1 = random_num(chunk_num);
          out_buf = delete_chunk(out_buf, &out_len, map, out_tree,
                                 all_chunks[index1]);
          break;
        };
        case 2: {
          printf("exchange chunk\n");
          index1 = random_num(chunk_num);
          out_buf =
              exchange_chunk(out_buf, out_len, out_tree, all_chunks[index1]);
          break;
        }
      }
    }
    if (out_len < len) {
      out_buf = realloc(out_buf, len);
    }
    out_len = len;
    memcpy(out_buf, buf, len);
    free_tree(out_tree, True);
    out_tree = chunk_duplicate(tree, True);
    map->clear(map);
    free(map);
    map = createHashMap(NULL, NULL);
    tree_add_map(out_tree->son, map);
  }
  freeHashMapIterator(&map_iter);
  free_tree(tree, True);
  free_tree(out_tree, True);
  map->clear(map);
  free(map);
  free(all_chunks);
  free(out_buf);
}

void struct_describing_stage(uint8_t *buf, uint32_t len, cJSON *json) {}

void describing_aware_stage(uint8_t *buf, uint32_t len, cJSON *json,
                            Track *track) {
  uint32_t out_len;
  uint32_t stage_max, stage_cur, index1, index2;
  int32_t i;
  uint8_t *out_buf;
  Chunk *tree, *out_tree;
  Enum *enum_iter;
  Length *length_iter;
  Offset *offset_iter;
  Constraint *cons_iter;
  tree = get_tree(json);
  HashMap map = createHashMap(NULL, NULL);
  out_len = len;
  out_buf = malloc(len);
  memcpy(out_buf, buf, len);
  out_tree = chunk_duplicate(tree, True);
  tree_add_map(out_tree->son, map);
  /*mutation enum*/
  enum_iter = track->enums;
  while (enum_iter) {
    uint32_t last_len = 0, stage_cur_byte;
    Chunk *cur_chunk;
    for (i = 0; i < enum_iter->cans_num; i++) {
      last_len = strlen(enum_iter->candidates[i]);
      cur_chunk = map->get(map, enum_iter->id);
      if (cur_chunk == NULL) {
        continue;
      }
      stage_cur_byte = get_chunk_abs_start(cur_chunk);
      if (stage_cur_byte < 0 || (stage_cur_byte + last_len) > len) {
        continue;
      }
      if ((cur_chunk->end - cur_chunk->start) < last_len) {
        continue;
      }
      /* new testcase */
      memcpy(out_buf + stage_cur_byte, enum_iter->candidates[i], last_len);

      /*save testcase if interesting */

      /* Restore all the clobbered memory */
      memcpy(out_buf + stage_cur_byte, buf, last_len);
    }
    enum_iter = enum_iter->next;
  }

  /*mutation length*/
  length_iter = track->lengths;
  while (length_iter) {
    Chunk *meta_chunk, *payload_chunk, *father;
    uint32_t meta_len, payload_len;
    uint32_t start;
    meta_len = payload_len = 0;
    /* add to length field */
    for (i = 1; i < 36; i++) {
      if (i > out_len) {
        break;
      }
      meta_chunk = map->get(map, length_iter->id1);
      payload_chunk = map->get(map, length_iter->id2);
      if (meta_chunk == NULL || payload_chunk == NULL) {
        continue;
      }
      meta_len = meta_chunk->end - meta_chunk->start;
      payload_len = payload_chunk->end - payload_chunk->start;
      if (meta_len != 1 && meta_len != 2 && meta_len != 4) {
        continue;
      }
      number_add(out_buf, meta_chunk, i);
      start = random_num(out_len - i);
      /* new testcase */
      out_buf = copy_and_insert(out_buf, &out_len,
                                get_chunk_abs_end(payload_chunk), start, i);
      /* update tree structure */
      payload_chunk->end += i;
      father = payload_chunk->father;
      while (father) {
        father->end += i;
        if (father->next) {
          chunk_add_len(father->next, i);
        }
        father = father->father;
      }
      if (payload_chunk->next) {
        chunk_add_len(payload_chunk->next, i);
      }

      /* save testcase if interesting */

      /* Recover all the clobbered stucture */
      if (out_len < len) {
        out_buf = realloc(out_buf, len);
      }
      out_len = len;
      memcpy(out_buf, buf, len);
      free_tree(out_tree, True);
      out_tree = chunk_duplicate(tree, True);
      map->clear(map);
      free(map);
      map = createHashMap(NULL, NULL);
      tree_add_map(out_tree->son, map);
    }

    /* delete from length field */
    for (i = 0; i < payload_len; i++) {
      meta_chunk = map->get(map, length_iter->id1);
      payload_chunk = map->get(map, length_iter->id2);
      if (meta_chunk == NULL || payload_chunk == NULL) {
        continue;
      }
      meta_len = meta_chunk->end - meta_chunk->start;
      payload_len = payload_chunk->end - payload_chunk->start;
      if (meta_len != 1 && meta_len != 2 && meta_len != 4) {
        continue;
      }
      number_add(out_buf, meta_chunk, -i);
      /* new testcase */
      out_buf =
          delete_data(out_buf, &out_len, get_chunk_abs_start(payload_chunk), i);
      /* update tree structure */
      payload_chunk->end -= i;
      father = payload_chunk->father;
      while (father) {
        father->end -= i;
        if (father->next) {
          chunk_add_len(father->next, -i);
        }
        father = father->father;
      }
      if (payload_chunk->next) {
        chunk_add_len(payload_chunk->next, -i);
      }

      /* save testcase if interesting */

      /* Recover all the clobbered stucture */
      if (out_len < len) {
        out_buf = realloc(out_buf, len);
      }
      out_len = len;
      memcpy(out_buf, buf, len);
      free_tree(out_tree, True);
      out_tree = chunk_duplicate(tree, True);
      map->clear(map);
      free(map);
      map = createHashMap(NULL, NULL);
      tree_add_map(out_tree->son, map);
    }
    length_iter = length_iter->next;
  }

  /*mutation offset*/
  offset_iter = track->offsets;
  while (offset_iter) {
    Chunk *meta_chunk, *payload_chunk;
    uint32_t meta_length;
    /* add offset field */
    for (i = 1; i < 36; i++) {
      if (i > out_len) {
        break;
      }
      meta_chunk = map->get(map, offset_iter->id1);
      if (meta_chunk == NULL) {
        continue;
      }
      meta_length = meta_chunk->end - meta_chunk->start;
      if (meta_length != 1 && meta_length != 2 && meta_length != 4) {
        continue;
      }
      number_add(out_buf, meta_chunk, i);
      Chunk *block = malloc(sizeof(Chunk));
      block->start = 0;
      block->end = i;
      block->id = malloc(strlen(meta_chunk->id) + 1);
      block->next = block->prev = block->father = block->son = NULL;
      strcpy(block->id, meta_chunk->id);
      set_id_add_map(block, map);
      chunk_insert(meta_chunk, block);

      /* new testcase */
      out_buf = copy_and_insert(out_buf, &out_len, meta_chunk->end,
                                random_num(out_len - i), i);

      /* save testcase if interesting */

      /* Recover all the clobbered stucture */
      if (out_len < len) {
        out_buf = realloc(out_buf, len);
      }
      out_len = len;
      memcpy(out_buf, buf, len);
      free_tree(out_tree, True);
      out_tree = chunk_duplicate(tree, True);
      map->clear(map);
      free(map);
      map = createHashMap(NULL, NULL);
      tree_add_map(out_tree->son, map);
    }
    offset_iter = offset_iter->next;
  }

  /*mutation constraint*/
  cons_iter = track->constraints;
  while (cons_iter) {
    cons_iter = cons_iter->next;
  }
  free_tree(tree, True);
  free_tree(out_tree, True);
  map->clear(map);
  free(map);
  free(out_buf);
}

int main() {
  uint8_t *in_buf, *out_buf;
  int32_t fd, len, n, chunk_num, temp_len;
  uint32_t clone_from, clone_to, clone_len;
  struct stat st;
  uint8_t **all_chunks;
  lstat(
      "/home/dp/Documents/fuzzing/chunk-afl/chunk_based_mutation/jpeg/"
      "not_kitty.jpg",
      &st);
  fd = open(
      "/home/dp/Documents/fuzzing/chunk-afl/chunk_based_mutation/jpeg/"
      "not_kitty.jpg",
      O_RDONLY);
  if (fd < 0) {
    printf("open fail\n");
    exit(-1);
  }
  len = st.st_size;
  in_buf = calloc(len, sizeof(char));
  n = read(fd, in_buf, len);
  out_buf = calloc(len, sizeof(char));
  memcpy(out_buf, in_buf, len);
  cJSON *in_json, *out_json, *target_json, *json_iter, *target_iter;
  in_json = parse_json(
      "/home/dp/Documents/fuzzing/chunk-afl/chunk_based_mutation/jpeg/"
      "not_kitty.jpg.json");
  out_json = cJSON_Duplicate(in_json, 1);

  // struct_havoc_stage(in_buf, len, in_json);

  Track *track = parse_track_file(
      "/home/dp/Documents/fuzzing/chunk-afl/chunk_based_mutation/jpeg/"
      "track.txt");

  // describing_aware_stage(in_buf, len, in_json, track);

  Chunk *tree = json_to_tree(in_json);
  Chunk *dup_tree = json_to_tree(in_json);
  Chunk *split_tree = NULL;
  split_tree = splice_tree(tree, dup_tree, 100);

  free_tree(split_tree, True);
  free_track(track);

  close(fd);
  // close(fd1);
  cJSON_Delete(out_json);
  cJSON_Delete(in_json);
  free(in_buf);
  free(out_buf);
  // free(log);
}