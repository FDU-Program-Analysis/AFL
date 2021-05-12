#include "afl-fuzz.h"

/* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */

static u8 could_be_bitflip(u32 xor_val) {
  u32 sh = 0;

  if (!xor_val) return 1;

  /* Shift left until first bit set. */

  while (!(xor_val & 1)) {
    sh++;
    xor_val >>= 1;
  }

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */

  if (xor_val == 1 || xor_val == 3 || xor_val == 15) return 1;

  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */

  if (sh & 7) return 0;

  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff) return 1;

  return 0;
}

/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */

static u8 could_be_arith(u32 old_val, u32 new_val, u8 blen) {
  u32 i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) return 1;

  /* See if one-byte adjustments to any byte could produce this result. */

  for (i = 0; i < blen; i++) {
    u8 a = old_val >> (8 * i), b = new_val >> (8 * i);

    if (a != b) {
      diffs++;
      ov = a;
      nv = b;
    }
  }

  /* If only one byte differs and the values are within range, return 1. */

  if (diffs == 1) {
    if ((u8)(ov - nv) <= ARITH_MAX || (u8)(nv - ov) <= ARITH_MAX) return 1;
  }

  if (blen == 1) return 0;

  /* See if two-byte adjustments to any byte would produce this result. */

  diffs = 0;

  for (i = 0; i < blen / 2; i++) {
    u16 a = old_val >> (16 * i), b = new_val >> (16 * i);

    if (a != b) {
      diffs++;
      ov = a;
      nv = b;
    }
  }

  /* If only one word differs and the values are within range, return 1. */

  if (diffs == 1) {
    if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX) return 1;

    ov = SWAP16(ov);
    nv = SWAP16(nv);

    if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX) return 1;
  }

  /* Finally, let's do the same thing for dwords. */

  if (blen == 4) {
    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX)
      return 1;

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX)
      return 1;
  }

  return 0;
}

/* Last but not least, a similar helper to see if insertion of an
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */

static u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le) {
  u32 i, j;

  if (old_val == new_val) return 1;

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */

  for (i = 0; i < blen; i++) {
    for (j = 0; j < sizeof(interesting_8); j++) {
      u32 tval =
          (old_val & ~(0xff << (i * 8))) | (((u8)interesting_8[j]) << (i * 8));

      if (new_val == tval) return 1;
    }
  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */

  if (blen == 2 && !check_le) return 0;

  /* See if two-byte insertions over old_val could give us new_val. */

  for (i = 0; i < blen - 1; i++) {
    for (j = 0; j < sizeof(interesting_16) / 2; j++) {
      u32 tval = (old_val & ~(0xffff << (i * 8))) |
                 (((u16)interesting_16[j]) << (i * 8));

      if (new_val == tval) return 1;

      /* Continue here only if blen > 2. */

      if (blen > 2) {
        tval = (old_val & ~(0xffff << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval) return 1;
      }
    }
  }

  if (blen == 4 && check_le) {
    /* See if four-byte insertions could produce the same result
       (LE only). */

    for (j = 0; j < sizeof(interesting_32) / 4; j++)
      if (new_val == (u32)interesting_32[j]) return 1;
  }

  return 0;
}

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

u8 *get_json_type(const cJSON *chunk) {
  if (cJSON_HasObjectItem(chunk, "type")) {
    return cJSON_GetObjectItemCaseSensitive(chunk, "type")->valuestring;
  }
  return NULL;
}

u32 get_chunk_abs_start(const Chunk *chunk) {
  u32 start = chunk->start;
  const Chunk *father;
  father = chunk->father;
  while (father != NULL) {
    start += father->start;
    father = father->father;
  }
  return start;
}

u32 get_chunk_abs_end(const Chunk *chunk) {
  u32 end = chunk->end;
  const Chunk *father;
  father = chunk->father;
  while (father != NULL) {
    end += father->start;
    father = father->father;
  }
  return end;
}

Node *get_node_list(Chunk *tree) {
  Chunk *iter;
  Node *head, *top;
  head = top = NULL;
  iter = tree;
  while (iter != NULL) {
    if (iter->son == NULL) {
      Node *node = ck_alloc(sizeof(Node));
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
      while (top->next != NULL) {
        top = top->next;
      }
    }
    iter = iter->next;
  }
  return head;
}

void free_node_list(Node *head) {
  Node *item = NULL;
  while (head != NULL) {
    item = head->next;
    ck_free(head);
    head = item;
  }
}

u8 *generate_id(char *str) {
  int i, UR, seed_str_len, len;
  struct timeval tv;
  unsigned int seed_num;
  char *random_str;
  char seed_str[] =
      "abcdefghijklmnopqrstuvwxyz"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-<>[]{}=*&^#:";
  len = 16;
  seed_str_len = strlen(seed_str);

  gettimeofday(&tv, NULL);
  seed_num = (unsigned int)(tv.tv_sec + tv.tv_usec);
  srand(seed_num);

  ck_free(str);
  random_str = ck_alloc(len);
  // len = strlen(random_str);
  for (i = 0; i < len - 1; i++) {
    UR = rand() % seed_str_len;
    random_str[i] = seed_str[UR];
  }
  random_str[len - 1] = '\0';
  return random_str;
}

Chunk *json_to_tree(cJSON *cjson_head) {
  u32 chunk_num = cJSON_GetArraySize(cjson_head);
  Chunk *head, *top, *iter;
  head = top = NULL;
  for (u32 i = 0; i < chunk_num; i++) {
    cJSON *chunk = cJSON_GetArrayItem(cjson_head, i);
    if (!chunk) {
      continue;
    }
    int32_t start = get_json_start(chunk);
    int32_t end = get_json_end(chunk);
    if (start < 0 || end < 0) {
      continue;
    }
    Chunk *node = ck_alloc(sizeof(Chunk));
    node->start = start;
    node->end = end;
    node->id = (u8 *)ck_alloc(strlen(chunk->string) + 1);
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
      while (iter != NULL) {
        iter->father = top;
        iter = iter->next;
      }
    }
  }
  return head;
}

Chunk *get_tree(cJSON *cjson_head) {
  Chunk *head, *root, *iter;
  u32 end;
  head = json_to_tree(cjson_head);
  if (head->next) {
    root = ck_alloc(sizeof(Chunk));
    root->son = head;
    root->start = head->start;
    iter = head;
    while (iter != NULL) {
      iter->father = root;
      end = iter->end;
      iter = iter->next;
    }
    root->end = end;
    root->id = "root";
    root->cons = NULL;
    root->father = root->next = root->prev = NULL;
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
  while (iter != NULL) {
    cJSON *cjson = cJSON_CreateObject();
    cJSON_AddNumberToObject(cjson, "start", iter->start);
    cJSON_AddNumberToObject(cjson, "end", iter->end);
    if (iter->son != NULL) {
      cJSON_AddItemToObject(cjson, "son", tree_to_json(iter->son));
    }
    cJSON_AddItemToObject(json_head, iter->id, cjson);
    iter = iter->next;
  }
  return json_head;
}

void tree_add_map(Chunk *head, HashMap map) {
  Chunk *iter = head;
  while (iter != NULL) {
    map->put(map, iter->id, iter);
    if (iter->son != NULL) {
      tree_add_map(iter->son, map);
    }
    iter = iter->next;
  }
}

void free_tree(Chunk *head, Boolean recurse) {
  if (head == NULL) {
    return;
  }
  Chunk *iter = NULL;
  while (head != NULL) {
    if (recurse) {
      iter = head->next;
    } else {
      iter = NULL;
    }
    ck_free(head->id);
    head->id = NULL;
    if (head->cons != NULL) {
      ck_free(head->cons);
    }
    if (head->son) {
      free_tree(head->son, True);
    }
    ck_free(head);
    head = iter;
  }
}

u32 htoi(u8 s[]) {
  u32 i;
  u32 n = 0;
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    i = 2;
  } else {
    i = 0;
  }
  for (; (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') ||
         (s[i] >= 'A' && s[i] <= 'Z');
       ++i) {
    if (tolower(s[i]) > '9') {
      n = 16 * n + (10 + tolower(s[i]) - 'a');
    } else {
      n = 16 * n + (tolower(s[i]) - '0');
    }
  }
  return n;
}

u8 *str_reverse(char *str) {
  u32 n = strlen(str) / 2;
  u32 i = 0;
  u8 tmp = 0;
  for (i = 0; i < n; i++) {
    tmp = str[i];
    str[i] = str[strlen(str) - i - 1];
    str[strlen(str) - i - 1] = tmp;
  }
  return str;
}

u8 *parse_candidate(u8 *str) {
  u8 *delim, *part, *candi, c, buffer[1024];
  u32 num, i;
  delim = "[], ";
  part = strtok(str, delim);
  i = 0;
  while (part != NULL) {
    num = htoi(part);
    c = num;
    buffer[i] = c;
    i++;
    part = strtok(NULL, delim);
  }
  candi = ck_alloc(i + 1);
  memcpy(candi, buffer, i);
  candi[i] = '\0';
  ck_free(str);
  return candi;
}

Track *parse_track_file(u8 *path) {
  FILE *fp;
  u8 buffer[1024] = {};
  u8 *delim, *id1, *id2, *type, *n;
  u32 num, i;
  Track *track;
  Enum *enum_top = NULL;
  Offset *offset_top = NULL;
  Length *length_top = NULL;
  Constraint *cons_top = NULL;
  track = ck_alloc(sizeof(struct Track));
  track->constraints = NULL;
  track->lengths = NULL;
  track->offsets = NULL;
  track->enums = NULL;
  delim = "();{}";
  id1 = id2 = type = n = NULL;
  if ((fp = fopen(path, "r")) == NULL) {
    PFATAL("Unable to access %s\n", path);
  }
  while (!feof(fp)) {
    n = fgets(buffer, 1024, fp);
    if (n == NULL) {
      continue;
    }
    id1 = strtok(buffer, delim);
    id2 = strtok(NULL, delim);
    type = strtok(NULL, delim);
    if (id1 == NULL || id2 == NULL || type == NULL) {
      continue;
    }
    if (strcmp(type, "Enum") == 0) {
      u8 *candidate;
      num = atoi(strtok(NULL, delim));
      Enum *enum_chunk = ck_alloc(sizeof(struct Enum) + num * 2 * sizeof(u8 *));
      enum_chunk->id = (u8 *)ck_alloc(strlen(id1) + 1);
      strcpy(enum_chunk->id, id1);
      enum_chunk->cans_num = num * 2;
      enum_chunk->next = NULL;
      for (i = 0; i < num; i++) {
        candidate = strtok(NULL, delim);
        enum_chunk->candidates[i] = ck_alloc(strlen(candidate) + 1);
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
      Length *len_chunk = ck_alloc(sizeof(struct Length));
      len_chunk->id1 = (u8 *)ck_alloc(strlen(id1) + 1);
      len_chunk->id2 = (u8 *)ck_alloc(strlen(id2) + 1);
      strcpy(len_chunk->id1, id1);
      strcpy(len_chunk->id2, id2);
      len_chunk->next = NULL;
      if (length_top) {
        length_top->next = len_chunk;
        length_top = len_chunk;
      } else {
        track->lengths = length_top = len_chunk;
      }
    } else if (strcmp(type, "Offset") == 0) {
      Offset *offset_chunk = ck_alloc(sizeof(struct Offset));
      num = atoi(strtok(NULL, delim));
      offset_chunk->id1 = (u8 *)ck_alloc(strlen(id1) + 1);
      strcpy(offset_chunk->id1, id1);
      offset_chunk->id2 = (u8 *)ck_alloc(strlen(id2) + 1);
      strcpy(offset_chunk->id2, id2);
      offset_chunk->abs = num;
      offset_chunk->next = NULL;
      if (offset_top) {
        offset_top->next = offset_chunk;
        offset_top = offset_chunk;
      } else {
        track->offsets = offset_top = offset_chunk;
      }
    } else if (strcmp(type, "Constraint") == 0) {
      Constraint *cons_chunk = ck_alloc(sizeof(struct Constraint));
      num = atoi(strtok(NULL, delim));
      cons_chunk->id1 = (u8 *)ck_alloc(strlen(id1) + 1);
      cons_chunk->id2 = (u8 *)ck_alloc(strlen(id2) + 1);
      strcpy(cons_chunk->id1, id1);
      strcpy(cons_chunk->id2, id2);
      cons_chunk->type = num;
      cons_chunk->next = NULL;
      if (cons_top) {
        cons_top->next = cons_chunk;
        cons_top = cons_chunk;
      } else {
        cons_top = track->constraints = cons_chunk;
      }
    }
  }
  enum_top = track->enums;
  while (enum_top != NULL) {
    num = enum_top->cans_num / 2;
    for (i = 0; i < num; i++) {
      enum_top->candidates[i] = parse_candidate(enum_top->candidates[i]);
      enum_top->candidates[i + num] =
          ck_alloc(strlen(enum_top->candidates[i]) + 1);
      strcpy(enum_top->candidates[i + num], enum_top->candidates[i]);
      enum_top->candidates[i + num] =
          str_reverse(enum_top->candidates[i + num]);
    }
    enum_top = enum_top->next;
  }
  fclose(fp);
  return track;
}

void free_enum(Enum *node) {
  ck_free(node->id);
  u32 i;
  for (i = 0; i < node->cans_num; i++) {
    ck_free(node->candidates[i]);
  }
  ck_free(node);
}

void free_length(Length *node) {
  ck_free(node->id1);
  ck_free(node->id2);
  ck_free(node);
}

void free_offset(Offset *node) {
  ck_free(node->id1);
  ck_free(node->id2);
  ck_free(node);
}

void free_constraint(Constraint *node) {
  ck_free(node->id1);
  ck_free(node->id2);
  ck_free(node);
}

void free_track(Track *track) {
  Enum *enum_next = NULL;
  Constraint *cons_next = NULL;
  Length *len_next = NULL;
  Offset *offset_next = NULL;
  if(track == NULL) {
    return;
  }
  while (track->offsets != NULL) {
    offset_next = track->offsets->next;
    free_offset(track->offsets);
    track->offsets = offset_next;
  }

  while (track->enums != NULL) {
    enum_next = track->enums->next;
    free_enum(track->enums);
    track->enums = enum_next;
  }

  while (track->constraints != NULL) {
    cons_next = track->constraints->next;
    free_constraint(track->constraints);
    track->constraints = cons_next;
  }

  while (track->lengths != NULL) {
    len_next = track->lengths->next;
    free_length(track->lengths);
    track->lengths = len_next;
  }
  ck_free(track);
}

struct Node *merge(struct Node *head1, struct Node *head2) {
  struct Node *dummyHead = ck_alloc(sizeof(struct Node));
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
  ck_free(dummyHead);
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

cJSON *parse_json(const u8 *format_file) {
  cJSON *cjson_head;
  s32 fd;
  u8 *in_buf;
  struct stat st;
  s32 n;
  if (lstat(format_file, &st)) {
    PFATAL("Unable to access %s\n", format_file);
  }
  fd = open(format_file, O_RDONLY);
  in_buf = ck_alloc(st.st_size);
  n = read(fd, in_buf, st.st_size);
  if (n < st.st_size) {
    PFATAL("Short read '%s'", format_file);
  }
  cjson_head = cJSON_ParseWithLength(in_buf, st.st_size);
  if (cjson_head == NULL) {
    PFATAL("Unable to parse '%s'", format_file);
  }
  close(fd);
  ck_free(in_buf);
  return cjson_head;
}

Chunk *find_chunk(u8 *id, Chunk *head) {
  Chunk *iter, *result;
  iter = head;
  while (iter != NULL) {
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

u8 is_inner_chunk(Chunk *father, Chunk *son) {
  Chunk *iter;
  iter = son->father;
  while (iter != NULL) {
    if (strcmp(father->id, iter->id) == 0) {
      return 1;
    }
    iter = iter->father;
  }
  return 0;
}

void chunk_add_len(Chunk *head, int32_t len) {
  Chunk *iter = head;
  while (iter != NULL) {
    iter->start += len;
    iter->end += len;
    iter = iter->next;
  }
}

Chunk *chunk_duplicate(Chunk *head, Boolean recurse) {
  Chunk *dup_head, *top, *iter, *temp;
  dup_head = top = temp = NULL;
  iter = head;
  while (iter != NULL) {
    Chunk *node = ck_alloc(sizeof(Chunk));
    node->start = iter->start;
    node->end = iter->end;
    node->id = (u8 *)ck_alloc(strlen(iter->id) + 1);
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
      while (temp != NULL) {
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
  Chunk *father, *temp;
  father = item->father;
  u32 delete_len = item->end - item->start;
  while (father != NULL) {
    temp = father->father;
    father->end -= delete_len;
    if (father->next) {
      chunk_add_len(father->next, -delete_len);
    }
    father = temp;
  }
  if (item->next != NULL) {
    chunk_add_len(item->next, -delete_len);
  }
  if (item->prev != NULL) {
    if (item->next != NULL) {
      item->prev->next = item->next;
      item->next->prev = item->prev;
    } else {
      item->prev->next = NULL;
    }
  } else if (item->father != NULL) {
    if (item->next != NULL) {
      item->father->son = item->next;
      item->next->prev = NULL;
    } else {
      item->father->son = NULL;
    }
  }
}

void chunk_insert(Chunk *item, Chunk *insert) {
  u32 len;
  len = insert->end - insert->start;
  chunk_add_len(insert, item->end - insert->start);
  Chunk *father = item->father;
  while (father != NULL) {
    father->end += len;
    if (father->next) {
      chunk_add_len(father->next, len);
    }
    father = father->father;
  }
  if (item->next) {
    chunk_add_len(item->next, len);
  }
  if (item->next) {
    item->next->prev = insert;
    insert->next = item->next;
  } else {
    insert->next = NULL;
  }
  item->next = insert;
  insert->prev = item;

  insert->father = item->father;
}

u8 *copy_and_insert(u8 *buf, u32 *len, u32 insert_at, u32 copy_start,
                    u32 copy_len) {
  u8 *new_buf;
  new_buf = ck_alloc(*len + copy_len);

  memcpy(new_buf, buf, insert_at);
  memcpy(new_buf + insert_at, buf + copy_start, copy_len);
  memcpy(new_buf + insert_at + copy_len, buf + insert_at, *len - insert_at);

  *len += copy_len;
  ck_free(buf);
  return new_buf;
}

void set_id_add_map(Chunk *head, HashMap map) {
  Chunk *iter = head;
  while (iter != NULL) {
    while (map->exists(map, iter->id)) {
      iter->id = generate_id(iter->id);
    }
    map->put(map, iter->id, iter);
    if (iter->son != NULL) {
      set_id_add_map(iter->son, map);
    }
    iter = iter->next;
  }
}

void delete_from_map(Chunk *head, HashMap map, Boolean recurse) {
  if (map == NULL) {
    return;
  }
  Chunk *iter = head;
  while (iter != NULL) {
    map->remove(map, iter->id);
    if (iter->son) {
      delete_from_map(iter->son, map, True);
    }
    if (recurse) {
      iter = iter->next;
    } else {
      iter = NULL;
    }
  }
}

u8 *insert_chunk(u8 *buf, u32 *len, HashMap map, Chunk *head, u8 *chunk_id,
                 u8 *insert_id, Boolean after) {
  u32 clone_len;
  u8 *new_buf;
  Chunk *chunk_choose = find_chunk(chunk_id, head);
  Chunk *item = find_chunk(insert_id, head);
  Chunk *temp;
  temp = NULL;
  if (item == NULL || chunk_choose == NULL) {
    return buf;
  }
  clone_len = chunk_choose->end - chunk_choose->start;
  if (clone_len == 0) {
    return buf;
  }
  Chunk *chunk_dup = chunk_duplicate(chunk_choose, False);
  if (!after) {
    if (item->prev) {
      item = item->prev;
    } else {
      temp = ck_alloc(sizeof(Chunk));
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
      ck_free(temp);
    }
  }
  return new_buf;
}

u8 *delete_data(u8 *buf, u32 *len, u32 delete_start, u32 delete_len) {
  u8 *new_buf;
  new_buf = ck_alloc(*len - delete_len);
  memcpy(new_buf, buf, delete_start);
  memcpy(new_buf + delete_start, buf + delete_start + delete_len,
         *len - delete_start - delete_len);
  *len -= delete_len;
  ck_free(buf);
  return new_buf;
}

u8 *delete_chunk(u8 *buf, u32 *len, HashMap map, Chunk *head, u8 *id) {
  Chunk *chunk_delete = find_chunk(id, head);
  Chunk *father;
  if (chunk_delete == NULL) {
    return buf;
  }
  u32 delete_start = get_chunk_abs_start(chunk_delete);
  u32 delete_len = chunk_delete->end - chunk_delete->start;
  if (delete_len >= *len) {
    return buf;
  }
  chunk_detach(head, chunk_delete);
  delete_from_map(chunk_delete, map, False);
  father = chunk_delete->father;
  free_tree(chunk_delete, False);
  while (father != NULL && father->start == father->end) {
    chunk_delete = father->father;
    chunk_detach(head, father);
    delete_from_map(father, map, False);
    free_tree(father, False);
    father = chunk_delete;
  }
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

Chunk *random_chunk(Chunk *head) {
  Chunk *reserve, *iter;
  u32 count, rand;
  reserve = NULL;
  iter = head;
  count = 0;
  while (iter != NULL) {
    count += 1;
    rand = UR(count) + 1;
    if (rand == count) {
      reserve = iter;
    }
    iter = iter->next;
  }
  return reserve;
}

void get_exchange_chunks(uint32_t chunk_num, uint8_t **all_chunks, HashMap map,
                         Chunk **chunks) {
  uint32_t index1 = UR(chunk_num);
  Chunk *chunk_left, *chunk_right, *temp;
  chunk_left = map->get(map, all_chunks[index1]);
  if (chunk_left == NULL) {
    return;
  }
  if (chunk_left->father == NULL) {
    return;
  }
  chunk_left = random_chunk(chunk_left->father->son);
  chunk_right = random_chunk(chunk_left->father->son);
  if (strcmp(chunk_left->id, chunk_right->id) == 0) {
    return;
  }
  if (get_chunk_abs_end(chunk_left) >= get_chunk_abs_end(chunk_right)) {
    temp = chunk_left;
    chunk_left = chunk_right;
    chunk_right = temp;
  }
  chunks[0] = chunk_left;
  chunks[1] = chunk_right;
}

uint8_t *exchange_chunk(uint8_t *buf, uint32_t len, Chunk *chunk_left,
                        Chunk *chunk_right) {
  Chunk *temp;
  uint32_t left_start, left_end, left_len, right_start, right_end, right_len;
  uint32_t gap;
  uint8_t *new_buf;
  if (chunk_left == NULL) {
    return buf;
  }
  if (chunk_left->father == NULL) {
    return buf;
  }
  left_start = get_chunk_abs_start(chunk_left);
  left_end = get_chunk_abs_end(chunk_left);
  right_start = get_chunk_abs_start(chunk_right);
  right_end = get_chunk_abs_end(chunk_right);
  new_buf = ck_alloc(len);
  memcpy(new_buf, buf, left_start);
  memcpy(new_buf + left_start, buf + right_start, right_end - right_start);
  memcpy(new_buf + left_start + right_end - right_start, buf + left_end,
         right_start - left_end);
  memcpy(new_buf + left_start + right_end - left_end, buf + left_start,
         left_end - left_start);
  memcpy(new_buf + right_end, buf + right_end, len - right_end);
  ck_free(buf);

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

void number_add(u8 *buf, Chunk *chunk, u32 num) {
  u32 chunk_start, chunk_len;
  chunk_start = get_chunk_abs_start(chunk);
  chunk_len = chunk->end - chunk->start;
  if (chunk_len == 1) {
    *(u8 *)(buf + chunk_start) += num;
  } else if (chunk_len == 2) {
    if (UR(2)) {
      *(u16 *)(buf + chunk_start) += num;
    } else {
      *(u16 *)(buf + chunk_start) =
          SWAP16(SWAP16(*(u16 *)(buf + chunk_start)) + num);
    }
  } else if (chunk_len == 4) {
    if (UR(2)) {
      *(u32 *)(buf + chunk_start) += num;
    } else {
      *(u32 *)(buf + chunk_start) =
          SWAP32(SWAP32(*(u32 *)(buf + chunk_start)) + num);
    }
  }
}

void number_subtract(u8 *buf, Chunk *chunk, u32 num) {
  u32 chunk_start, chunk_len;
  chunk_start = get_chunk_abs_start(chunk);
  chunk_len = chunk->end - chunk->start;
  if (chunk_len == 1) {
    *(u8 *)(buf + chunk_start) -= num;
  } else if (chunk_len == 2) {
    if (UR(2)) {
      *(u16 *)(buf + chunk_start) -= num;
    } else {
      *(u16 *)(buf + chunk_start) =
          SWAP16(SWAP16(*(u16 *)(buf + chunk_start)) - num);
    }
  } else if (chunk_len == 4) {
    if (UR(2)) {
      *(u32 *)(buf + chunk_start) -= num;
    } else {
      *(u32 *)(buf + chunk_start) =
          SWAP32(SWAP32(*(u32 *)(buf + chunk_start)) - num);
    }
  }
}

void number_set_interesting(u8 *buf, Chunk *chunk) {
  u32 chunk_len, chunk_start, index;
  chunk_len = chunk->end - chunk->start;
  chunk_start = get_chunk_abs_start(chunk);
  if (chunk_len == 1) {
    index = UR(sizeof(interesting_8));
    buf[chunk_start] = interesting_8[index];
  } else if (chunk_len == 2) {
    index = UR(sizeof(interesting_16) / 2);
    if (UR(2)) {
      *(u16 *)(buf + chunk_start) = interesting_16[index];
    } else {
      *(u16 *)(buf + chunk_start) = SWAP16(interesting_16[index]);
    }
  } else if (chunk_len == 4) {
    index = UR(sizeof(interesting_32) / 4);
    if (UR(2)) {
      *(u32 *)(buf + chunk_start) = interesting_32[index];
    } else {
      *(u32 *)(buf + chunk_start) = SWAP32(interesting_32[index]);
    }
  }
}

Chunk *find_chunk_include(Chunk *head, u32 num) {
  Chunk *iter;
  iter = head;
  while (iter != NULL) {
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

void insert_block(Chunk *head, u32 insert_to, u32 insert_len) {
  Chunk *item;
  if (insert_to == head->end) {
    item = find_chunk_include(head, insert_to - 1);
  } else {
    item = find_chunk_include(head, insert_to);
  }
  if (item == NULL) {
    return;
  }
  item->end += insert_len;
  Chunk *father = item->father;
  while (father != NULL) {
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

void delete_son_block(Chunk *head, HashMap map, u32 delete_from,
                      u32 delete_len) {
  Chunk *start_chunk, *end_chunk, *iter, *temp;
  start_chunk = head->son;
  if (start_chunk == NULL) {
    return;
  }
  while (start_chunk != NULL) {
    if (!((get_chunk_abs_start(start_chunk) <= delete_from) &&
          (get_chunk_abs_end(start_chunk) > delete_from))) {
      start_chunk = start_chunk->next;
    } else {
      break;
    }
  }
  if (start_chunk == NULL) {
    return;
  }
  end_chunk = start_chunk;
  while (end_chunk != NULL) {
    if (get_chunk_abs_end(end_chunk) < delete_from + delete_len) {
      end_chunk = end_chunk->next;
    } else {
      break;
    }
  }
  if (start_chunk == end_chunk) {
    delete_son_block(start_chunk, map, delete_from, delete_len);
    start_chunk->end -= delete_len;
    if (start_chunk->next) {
      chunk_add_len(start_chunk->next, -delete_len);
    }
    if (start_chunk->start == start_chunk->end) {
      chunk_detach(head, start_chunk);
      delete_from_map(start_chunk, map, False);
      free_tree(start_chunk, False);
    }
  } else {
    delete_son_block(start_chunk, map, delete_from,
                     get_chunk_abs_end(start_chunk) - delete_from);
    delete_son_block(end_chunk, map, get_chunk_abs_start(end_chunk),
                     delete_from + delete_len - get_chunk_abs_start(end_chunk));
    iter = start_chunk->next;
    while (iter != NULL && iter != end_chunk) {
      temp = iter->next;
      delete_from_map(iter, map, False);
      free_tree(iter, False);
      iter = temp;
    }
    start_chunk->next = end_chunk;
    end_chunk->prev = start_chunk;
    start_chunk->end =
        start_chunk->start + delete_from - get_chunk_abs_start(start_chunk);
    chunk_add_len(end_chunk, -delete_len);
    end_chunk->start = start_chunk->end;
    if (start_chunk->start == start_chunk->end) {
      chunk_detach(head, start_chunk);
      delete_from_map(start_chunk, map, False);
      free_tree(start_chunk, False);
      start_chunk = NULL;
    }
    if (end_chunk->start == end_chunk->end) {
      chunk_detach(head, end_chunk);
      delete_from_map(end_chunk, map, False);
      free_tree(end_chunk, False);
      end_chunk = NULL;
    }
  }
}

void delete_block(Chunk *head, HashMap map, u32 delete_from, u32 delete_len) {
  Chunk *item = find_chunk_include(head, delete_from);
  Chunk *father, *temp;
  if (item == NULL) {
    return;
  }
  while ((item != NULL) &&
         (get_chunk_abs_end(item) < delete_from + delete_len)) {
    item = item->father;
  }
  if (item == NULL) {
    return;
  }
  delete_son_block(item, map, delete_from, delete_len);
  item->end -= delete_len;
  father = item->father;
  if (item->next) {
    chunk_add_len(item->next, -delete_len);
  }
  if (item->start == item->end) {
    chunk_detach(head, item);
    delete_from_map(item, map, False);
    free_tree(item, False);
    item = NULL;
  }
  while (father != NULL) {
    temp = father->father;
    father->end -= delete_len;
    if (father->next) {
      chunk_add_len(father->next, -delete_len);
    }
    if (father->start == father->end) {
      chunk_detach(head, father);
      delete_from_map(father, map, False);
      free_tree(father, False);
      father = NULL;
    }
    father = temp;
  }
}

Chunk *splice_tree(Chunk *head1, Chunk *head2, u32 split_at) {
  if (split_at == 0) {
    free_tree(head1, True);
    return head2;
  }
  if (split_at == head1->end) {
    free_tree(head2, True);
    return head1;
  }
  Chunk *item1 = find_chunk_include(head1, split_at);
  Chunk *item2 = find_chunk_include(head2, split_at);
  Chunk *item1_root = item1;
  Chunk *item2_root = item2;
  Chunk *prev, *iter, *root, *temp;
  while (item1_root->father != NULL) {
    temp = item1_root->father;
    free_tree(item1_root->next, True);
    item1_root->next = NULL;
    item1_root->end =
        split_at - get_chunk_abs_start(item1_root) + item1_root->start;
    if (item1_root->start == item1_root->end) {
      chunk_detach(head1, item1_root);
      free_tree(item1_root, False);
    }
    item1_root = temp;
  }
  item1_root->end =
      split_at - get_chunk_abs_start(item1_root) + item1_root->start;

  while (item2_root->father != NULL) {
    prev = item2_root->prev;
    while (prev != NULL) {
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
  root = ck_alloc(sizeof(Chunk));
  root->father = root->next = root->prev = root->son = NULL;
  root->cons = NULL;
  root->start = 0;
  root->end = item2_root->end;
  root->id = ck_alloc(strlen(item1_root->id) + 1);
  strcpy(root->id, item1_root->id);
  set_id_add_map(item2_root, map);
  set_id_add_map(root, map);
  item1_root->next = item2_root;
  item2_root->prev = item1_root;
  root->son = item1_root;
  item1_root->father = root;
  item2_root->father = root;
  map->clear(map);
  free(map);
  return root;
}

Enum *get_random_enum(Enum *head) {
  Enum *reserve, *iter;
  u32 count, rand;
  reserve = NULL;
  iter = head;
  count = 0;
  while (iter != NULL) {
    count += 1;
    rand = UR(count) + 1;
    if (rand == count) {
      reserve = iter;
    }
    iter = iter->next;
  }
  return reserve;
}

Length *get_random_length(Length *head) {
  Length *reserve, *iter;
  u32 count, rand;
  reserve = NULL;
  iter = head;
  count = 0;
  while (iter != NULL) {
    count += 1;
    rand = UR(count) + 1;
    if (rand == count) {
      reserve = iter;
    }
    iter = iter->next;
  }
  return reserve;
}

Offset *get_random_offset(Offset *head) {
  Offset *reserve, *iter;
  reserve = NULL;
  u32 count, rand;
  iter = head;
  count = 0;
  while (iter != NULL) {
    count += 1;
    rand = UR(count) + 1;
    if (rand == count) {
      reserve = iter;
    }
    iter = iter->next;
  }
  return reserve;
}

Constraint *get_random_constraint(Constraint *head) {
  Constraint *reserve, *iter;
  u32 count, rand;
  reserve = NULL;
  iter = head;
  count = 0;
  while (iter != NULL) {
    count += 1;
    rand = UR(count) + 1;
    if (rand == count) {
      reserve = iter;
    }
    iter = iter->next;
  }
  return reserve;
}

uint8_t *itoh(uint32_t num) {
  uint8_t *buff;
  buff = ck_alloc(3);
  if (num / 16 < 10) {
    buff[0] = num / 16 + '0';
  } else {
    buff[0] = num / 16 - 10 + 'A';
  }
  if (num % 16 < 10) {
    buff[1] = num % 16 + '0';
  } else {
    buff[1] = num % 16 - 10 + 'A';
  }
  buff[2] = '\0';
  return buff;
}

uint8_t *candidate_to_str(uint8_t *str) {
  uint32_t len, i, num;
  uint8_t *cand_str = "", *buff, *temp = "";
  Boolean alloc = False;
  len = strlen(str);
  for (i = 0; i < len; i++) {
    num = str[i];
    buff = itoh(num);
    if (strcmp(cand_str, "") == 0) {
      cand_str = alloc_printf("[%s%s", temp, buff);
    } else {
      cand_str = alloc_printf("%s, %s", temp, buff);
    }
    if (alloc) {
      ck_free(temp);
    }
    ck_free(buff);
    temp = cand_str;
    alloc = True;
  }
  temp = cand_str;
  cand_str = alloc_printf("%s]", temp);
  if (strcmp(temp, "") != 0) {
    ck_free(temp);
  }
  return cand_str;
}

uint8_t *track_to_str(Track *track) {
  uint8_t *str = "", *track_str = "", *temp = "";
  uint8_t *cand_str;
  uint32_t i;
  Boolean alloc = False;
  Enum *enum_iter = NULL;
  Length *len_iter = NULL;
  Offset *offset_iter = NULL;
  Constraint *con_iter = NULL;
  enum_iter = track->enums;
  while (enum_iter != NULL) {
    str = alloc_printf("(%s;0000000000000000;Enum;%d;{", enum_iter->id,
                       enum_iter->cans_num / 2);
    track_str = alloc_printf("%s%s", temp, str);
    ck_free(str);
    if (alloc) {
      ck_free(temp);
    }
    for (i = 0; i < enum_iter->cans_num / 2; i++) {
      temp = track_str;
      cand_str = candidate_to_str(enum_iter->candidates[i]);
      track_str = alloc_printf("%s%s;", temp, cand_str);
      ck_free(cand_str);
      ck_free(temp);
    }
    temp = track_str;
    track_str = alloc_printf("%s})\n", temp);
    ck_free(temp);
    temp = track_str;
    alloc = True;
    enum_iter = enum_iter->next;
  }
  len_iter = track->lengths;
  while (len_iter != NULL) {
    str = alloc_printf("(%s;%s;Length;%d)\n", len_iter->id1, len_iter->id2, 0);
    track_str = alloc_printf("%s%s", temp, str);
    ck_free(str);
    if (alloc) {
      ck_free(temp);
    }
    temp = track_str;
    alloc = True;
    len_iter = len_iter->next;
  }
  offset_iter = track->offsets;
  while (offset_iter != NULL) {
    str = alloc_printf("(%s;%s;Offset;%d)\n", offset_iter->id1,
                       offset_iter->id2, 0);
    track_str = alloc_printf("%s%s", temp, str);
    ck_free(str);
    if (alloc) {
      ck_free(temp);
    }
    temp = track_str;
    alloc = True;
    offset_iter = offset_iter->next;
  }
  con_iter = track->constraints;
  while (con_iter != NULL) {
    str = alloc_printf("(%s;%s;Constraint;%d)\n", con_iter->id1, con_iter->id2,
                       0);
    track_str = alloc_printf("%s%s", temp, str);
    ck_free(str);
    if (alloc) {
      ck_free(temp);
    }
    temp = track_str;
    alloc = True;
    con_iter = con_iter->next;
  }
  return track_str;
}

Boolean check_tree(Chunk *head, HashMap map) {
  Chunk *iter;
  iter = head;
  while (iter != NULL) {
    if (map->exists(map, iter->id)) {
      printf("iter->id = %s, duplicate id\n", iter->id);
      return False;
    }
    map->put(map, iter->id, iter);
    if (iter->start == iter->end) {
      printf("iter->id = %s, iter->start == iter->end\n", iter->id);
      return False;
    }
    if (iter->prev != NULL) {
      if (iter->start != iter->prev->end) {
        printf("iter->prev end = %d\n", iter->prev->end);
        printf("iter->id = %s, iter->start != iter->prev->end\n", iter->id);
        return False;
      }
    } else if (iter->start != 0) {
      printf("iter->id = %s, iter->start != 0\n", iter->id);
      return False;
    }
    if (iter->father != NULL) {
      if (get_chunk_abs_end(iter) > get_chunk_abs_end(iter->father)) {
        printf(
            "iter->id= %s, get_chunk_abs_end(iter) > "
            "get_chunk_abs_end(iter->father)\n",
            iter->id);
        return False;
      }
    }
    if (iter->next == NULL && iter->father != NULL) {
      if (get_chunk_abs_end(iter) != get_chunk_abs_end(iter->father)) {
        printf(
            "iter->id = %s, get_chunk_abs_end(iter) != "
            "get_chunk_abs_end(iter->father)\n",
            iter->id);
        return False;
      }
    }
    if (iter->son != NULL) {
      if (check_tree(iter->son, map) == False) {
        return False;
      }
    }
    iter = iter->next;
  }
  return True;
}

void check(Chunk *tree) {
  HashMap map = createHashMap(NULL, NULL);
  if (check_tree(tree, map) == False) {
    PFATAL("%s\n", cJSON_Print(tree_to_json(tree)));
    free(map);
    exit(0);
  }
  map->clear(map);
  free(map);
}

void struct_havoc_stage(char **argv, u8 *buf, u32 len, Chunk *tree,
                        Track *track) {
  u8 **all_chunks;
  u32 chunk_num = 0, out_len;
  u32 stage_max, stage_cur, i, index1, index2;
  u64 orig_hit_cnt, new_hit_cnt;
  u8 *out_buf;
  Chunk *out_tree;
  Enum *enum_field = NULL;
  Length *len_field = NULL;
  Offset *offset_field = NULL;
  out_len = len;
  out_buf = ck_alloc(len);
  memcpy(out_buf, buf, len);
  out_tree = chunk_duplicate(tree, True);
  HashMap map = createHashMap(NULL, NULL);
  tree_add_map(tree->son, map);
  all_chunks = ck_alloc(map->size * sizeof(u8 *));
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
  stage_max = chunk_num * 16;
  stage_cur = 0;
  stage_name = "struct_havoc";
  stage_short = "chunkFuzzer1";
  orig_hit_cnt = queued_paths + unique_crashes;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    for (i = 0; i < 8; i++) {
      u32 num;
      num = UR(4 + ((track == NULL)? 0 : 10));
      switch (num) {
        case 0: {
          /* Randomly copy one chunk and insert before/after random chunk */
          index1 = UR(chunk_num);
          index2 = UR(chunk_num);
          out_buf = insert_chunk(out_buf, &out_len, map, out_tree,
                                 all_chunks[index1], all_chunks[index2], UR(2));
          break;
        };
        case 1 ... 2: {
          /* Randomly delete one chunk */
          index1 = UR(chunk_num);
          out_buf = delete_chunk(out_buf, &out_len, map, out_tree,
                                 all_chunks[index1]);
          break;
        };
        case 3: {
          /* Randomly exchange two chunks */
          Chunk *chunks[2];
          chunks[0] = NULL;
          chunks[1] = NULL;
          get_exchange_chunks(chunk_num, all_chunks, map, chunks);
          out_buf = exchange_chunk(out_buf, out_len, chunks[0], chunks[1]);
          break;
        }
        case 4: {
          /* Randomly replace one enum field to a legal candidate */
          enum_field = get_random_enum(track->enums);
          if (enum_field == NULL) {
            break;
          }
          Chunk *chunk = map->get(map, enum_field->id);
          if (chunk == NULL) {
            break;
          }
          u32 chunk_len = chunk->end - chunk->start;
          u32 num = UR(enum_field->cans_num);
          u32 candi_len = strlen(enum_field->candidates[num]);
          u32 copy_len = chunk_len > candi_len ? candi_len : chunk_len;
          memcpy(out_buf + get_chunk_abs_start(chunk),
                 enum_field->candidates[num], copy_len);
          break;
        }
        case 5 ... 6: {
          /* Randomly add/subtract to length/offset field, random endian */
          u8 *chunk_id;
          if (UR(2)) {
            len_field = get_random_length(track->lengths);
            if (len_field == NULL) {
              break;
            }
            chunk_id = len_field->id1;
          } else {
            offset_field = get_random_offset(track->offsets);
            if (offset_field == NULL) {
              break;
            }
            chunk_id = offset_field->id1;
          }
          Chunk *chunk = map->get(map, chunk_id);
          if (chunk == NULL) {
            break;
          }
          int32_t num = 1 + UR(ARITH_MAX);
          if (UR(2)) {
            number_add(out_buf, chunk, num);
          } else {
            number_subtract(out_buf, chunk, num);
          }
          break;
        }
        case 7 ... 8: {
          /* Randomly set length/offset to interesting value, random endian */
          u8 *chunk_id;
          if (UR(2)) {
            len_field = get_random_length(track->lengths);
            if (len_field == NULL) {
              break;
            }
            chunk_id = len_field->id1;
          } else {
            offset_field = get_random_offset(track->offsets);
            if (offset_field == NULL) {
              break;
            }
            chunk_id = offset_field->id1;
          }
          Chunk *chunk = map->get(map, chunk_id);
          if (chunk == NULL) {
            break;
          }
          number_set_interesting(out_buf, chunk);
          break;
        }
        case 9 ... 10: {
          /* Randomly insert data to length/offset payloads */
          u8 acturally_clone = UR(4);
          u32 clone_from, clone_to, clone_len;
          u8 *new_buf;
          u8 *chunk_id;
          if (UR(2)) {
            len_field = get_random_length(track->lengths);
            if (len_field == NULL) {
              break;
            }
            chunk_id = len_field->id2;
          } else {
            offset_field = get_random_offset(track->offsets);
            if (offset_field == NULL) {
              break;
            }
            chunk_id = offset_field->id2;
          }
          Chunk *chunk = map->get(map, chunk_id);
          if (chunk == NULL) {
            break;
          }
          if (acturally_clone) {
            clone_len = choose_block_len(out_len);
            clone_from = UR(out_len - clone_len + 1);
          } else {
            clone_len = choose_block_len(HAVOC_BLK_XL);
            clone_from = 0;
          }

          clone_to = get_chunk_abs_start(chunk) + UR(chunk->end - chunk->start);
          new_buf = ck_alloc(out_len + clone_len);

          /* Head */
          memcpy(new_buf, out_buf, clone_to);

          /* Inserted part */
          if (acturally_clone) {
            memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
          } else {
            memset(new_buf + clone_to, UR(2) ? UR(256) : out_buf[UR(out_len)],
                   clone_len);
          }

          /* Tail */
          memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                 out_len - clone_to);
          ck_free(out_buf);
          out_buf = new_buf;
          out_len += clone_len;
          /* Update tree structure */
          insert_block(out_tree, clone_to, clone_len);
          break;
        }
        case 11 ... 13: {
          /* Randomly delete data from offset/length payloads */
          u32 del_from, del_len;
          if (out_len < 2) {
            break;
          }
          u8 *chunk_id;
          if (UR(2)) {
            len_field = get_random_length(track->lengths);
            if (len_field == NULL) {
              break;
            }
            chunk_id = len_field->id2;
          } else {
            offset_field = get_random_offset(track->offsets);
            if (offset_field == NULL) {
              break;
            }
            chunk_id = offset_field->id2;
          }
          Chunk *chunk = map->get(map, chunk_id);
          if (chunk == NULL) {
            break;
          }
          if (chunk->end - chunk->start < 2) break;
          del_len = choose_block_len(chunk->end - chunk->start - 1);
          del_from = get_chunk_abs_start(chunk) + UR(chunk->end - chunk->start - del_len);
          memmove(out_buf + del_from, out_buf + del_from + del_len,
                  out_len - del_from - del_len);
          out_len -= del_len;

          /* Update tree structure */
          delete_block(out_tree, map, del_from, del_len);
          break;
        }
      }
    }

    if (common_fuzz_stuff(argv, out_buf, out_len, out_tree, track))
      goto exit_struct_havoc_stage;

    if (out_len < len) {
      out_buf = ck_realloc(out_buf, len);
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

  new_hit_cnt = queued_paths + unique_crashes;
  stage_finds[STAGE_STRUCT_HAVOC] += new_hit_cnt - orig_hit_cnt;
  stage_finds[STAGE_STRUCT_HAVOC] += stage_max;

exit_struct_havoc_stage:

  freeHashMapIterator(&map_iter);
  free_tree(out_tree, True);
  map->clear(map);
  free(map);
  ck_free(all_chunks);
  ck_free(out_buf);
}

void struct_describing_stage(u8 *buf, u32 len, cJSON *json) {}

void struct_aware_stage(char **argv, u8 *buf, u32 len, Chunk *tree,
                        Track *track) {
  if (track == NULL) {
    return;
  }
  u32 out_len;
  // u32 stage_max, stage_cur, index1, index2;
  int32_t i;
  u8 *out_buf;
  Chunk *out_tree;
  Enum *enum_iter;
  Length *length_iter;
  Offset *offset_iter;
  Constraint *cons_iter;
  u64 orig_hit_cnt, new_hit_cnt;
  HashMap map = createHashMap(NULL, NULL);
  out_len = len;
  out_buf = ck_alloc(len);
  memcpy(out_buf, buf, len);
  out_tree = chunk_duplicate(tree, True);
  tree_add_map(out_tree->son, map);
  stage_name = "describing aware";
  stage_short = "chunkFuzzer2";
  orig_hit_cnt = queued_paths + unique_crashes;
  /* Mutation enum field, repalce with legal candidates */
  enum_iter = track->enums;
  while (enum_iter != NULL) {
    u32 last_len = 0, stage_cur_byte;
    Chunk *cur_chunk;
    for (i = 0; i < enum_iter->cans_num; i++) {
      last_len = strlen(enum_iter->candidates[i]);
      cur_chunk = map->get(map, enum_iter->id);
      if (cur_chunk == NULL) {
        break;
      }
      stage_cur_byte = get_chunk_abs_start(cur_chunk);
      if (stage_cur_byte < 0 || (stage_cur_byte + last_len) > len) {
        break;
      }
      if ((cur_chunk->end - cur_chunk->start) < last_len) {
        break;
      }
      /* new testcase */
      memcpy(out_buf + stage_cur_byte, enum_iter->candidates[i], last_len);

      /*save testcase if interesting */
      if (common_fuzz_stuff(argv, out_buf, out_len, out_tree, track))
        goto exit_describing_aware_stage;

      /* Restore all the clobbered memory */
      memcpy(out_buf + stage_cur_byte, buf, last_len);
    }
    enum_iter = enum_iter->next;
  }

  /*mutation length*/
  length_iter = track->lengths;
  while (length_iter != NULL) {
    Chunk *meta_chunk, *payload_chunk;
    u32 meta_len, payload_len;
    u32 start;
    meta_len = payload_len = 0;
    meta_chunk = map->get(map, length_iter->id1);
    payload_chunk = map->get(map, length_iter->id2);
    if (meta_chunk == NULL || payload_chunk == NULL) {
      break;
    }
    meta_len = meta_chunk->end - meta_chunk->start;
    payload_len = payload_chunk->end - payload_chunk->start;
    if (meta_len != 1 && meta_len != 2 && meta_len != 4) {
      break;
    }
    /* add to length field */
    for (i = 0; i <= 36; i += 2) {
      if (i >= out_len) {
        break;
      }
      meta_chunk = map->get(map, length_iter->id1);
      payload_chunk = map->get(map, length_iter->id2);
      number_add(out_buf, meta_chunk, i);
      start = UR(out_len - i);
      /* new testcase */
      out_buf = copy_and_insert(out_buf, &out_len,
                                get_chunk_abs_end(payload_chunk), start, i);
      /* update tree structure */
      insert_block(out_tree, get_chunk_abs_end(payload_chunk) - 1, i);

      /* save testcase if interesting */
      if (common_fuzz_stuff(argv, out_buf, out_len, out_tree, track))
        goto exit_describing_aware_stage;

      /* Recover all the clobbered stucture */
      if (out_len < len) {
        out_buf = ck_realloc(out_buf, len);
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
    for (i = 2; i < payload_len; i += 2) {
      meta_chunk = map->get(map, length_iter->id1);
      payload_chunk = map->get(map, length_iter->id2);
      number_add(out_buf, meta_chunk, -i);
      /* new testcase */
      out_buf =
          delete_data(out_buf, &out_len, get_chunk_abs_start(payload_chunk), i);
      /* update tree structure */
      delete_block(out_tree, map, get_chunk_abs_start(payload_chunk), i);

      /* save testcase if interesting */
      if (common_fuzz_stuff(argv, out_buf, out_len, out_tree, track))
        goto exit_describing_aware_stage;

      /* Recover all the clobbered stucture */
      if (out_len < len) {
        out_buf = ck_realloc(out_buf, len);
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

    /* set interesting value */
    meta_chunk = map->get(map, length_iter->id1);
    u32 index = get_chunk_abs_start(meta_chunk);
    if (meta_chunk->end - meta_chunk->start == 1) {
      u8 orig = out_buf[index];
      for (i = 0; i < sizeof(interesting_8); i++) {
        out_buf[index] = interesting_8[i];
        if (common_fuzz_stuff(argv, out_buf, out_len, out_tree, track))
          goto exit_describing_aware_stage;
      }
      out_buf[index] = orig;
    } else if (meta_chunk->end - meta_chunk->start == 2) {
      u16 orig = *(u16 *)(out_buf + index);
      for (i = 0; i < sizeof(interesting_16) / 2; i++) {
        *(u16 *)(out_buf + index) = interesting_16[i];
        if (common_fuzz_stuff(argv, out_buf, out_len, out_tree, track))
          goto exit_describing_aware_stage;
        *(u16 *)(out_buf + index) = SWAP16(interesting_16[i]);
        if (common_fuzz_stuff(argv, out_buf, out_len, out_tree, track))
          goto exit_describing_aware_stage;
      }
      *(u16 *)(out_buf + index) = orig;
    } else if (meta_chunk->end - meta_chunk->start == 4) {
      u32 orig = *(u32 *)(out_buf + index);
      for (i = 0; i < sizeof(interesting_32) / 4; i++) {
        *(u32 *)(out_buf + index) = interesting_32[i];
        if (common_fuzz_stuff(argv, out_buf, out_len, out_tree, track))
          goto exit_describing_aware_stage;
        *(u32 *)(out_buf + index) = SWAP32(interesting_32[i]);
        if (common_fuzz_stuff(argv, out_buf, out_len, out_tree, track))
          goto exit_describing_aware_stage;
      }
      *(u32 *)(out_buf + index) = orig;
    }
    length_iter = length_iter->next;
  }

  /*mutation offset*/
  offset_iter = track->offsets;
  while (offset_iter != NULL) {
    Chunk *meta_chunk;
    u32 meta_length;
    /* add offset field */
    for (i = 1; i < 36; i++) {
      if (i > out_len) {
        break;
      }
      meta_chunk = map->get(map, offset_iter->id1);
      if (meta_chunk == NULL) {
        break;
      }
      meta_length = meta_chunk->end - meta_chunk->start;
      if (meta_length != 1 && meta_length != 2 && meta_length != 4) {
        break;
      }
      number_add(out_buf, meta_chunk, i);
      Chunk *block = ck_alloc(sizeof(Chunk));
      block->start = 0;
      block->end = i;
      block->id = ck_alloc(strlen(meta_chunk->id) + 1);
      block->next = block->prev = block->father = block->son = NULL;
      strcpy(block->id, meta_chunk->id);
      set_id_add_map(block, map);
      chunk_insert(meta_chunk, block);

      /* new testcase */
      out_buf = copy_and_insert(out_buf, &out_len, meta_chunk->end,
                                UR(out_len - i), i);

      /* save testcase if interesting */
      if (common_fuzz_stuff(argv, out_buf, out_len, out_tree, track))
        goto exit_describing_aware_stage;

      /* Recover all the clobbered stucture */
      if (out_len < len) {
        out_buf = ck_realloc(out_buf, len);
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
  while (cons_iter != NULL) {
    cons_iter = cons_iter->next;
  }

  new_hit_cnt = queued_paths + unique_crashes;
  stage_finds[STAGE_STRUCT_AWARE] += new_hit_cnt - orig_hit_cnt;

exit_describing_aware_stage:
  free_tree(out_tree, True);
  map->clear(map);
  free(map);
  ck_free(out_buf);
}

/* Take the current entry from the queue, fuzz it for a while. This
   function is a tad too long... returns 0 if fuzzed successfully, 1 if
   skipped or bailed out. */

u8 fuzz_one(char **argv) {
  s32 len, fd, temp_len, i, j;
  u8 *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  cJSON *in_json;
  u64 havoc_queued, orig_hit_cnt, new_hit_cnt;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;

  u8 ret_val = 1, doing_det = 0;

  u8 a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

  Node *list, *list_itr, *list_temp;
  list = list_itr = list_temp = NULL;

  Chunk *in_tree, *out_tree, *orig_tree;

  Track *track;
  u32 start = 0, end = 0, field_len = 0;

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (queue_cur->depth > 1) return 1;

#else

  if (pending_favored) {
    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
        UR(100) < SKIP_TO_NEW_PROB)
      return 1;
  } else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {
    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (queue_cycle > 1 && !queue_cur->was_fuzzed) {
      if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;

    } else {
      if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;
    }
  }

#endif /* ^IGNORE_FINDS */

  if (not_on_tty) {
    ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
         current_entry, queued_paths, unique_crashes);
    fflush(stdout);
  }

  /* Map the test case into memory. */

  fd = open(queue_cur->fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", queue_cur->fname);

  len = queue_cur->len;

  orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (orig_in == MAP_FAILED) PFATAL("Unable to mmap '%s'", queue_cur->fname);

  close(fd);

  in_json = parse_json(queue_cur->format_file);

  /* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
     single byte anyway, so it wouldn't give us any performance or memory usage
     benefits. */

  out_buf = ck_alloc_nozero(len);

  subseq_tmouts = 0;

  cur_depth = queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (queue_cur->cal_failed) {
    u8 res = FAULT_TMOUT;

    if (queue_cur->cal_failed < CAL_CHANCES) {
      /* Reset exec_cksum to tell calibrate_case to re-execute the testcase
         avoiding the usage of an invalid trace_bits.
         For more info: https://github.com/AFLplusplus/AFLplusplus/pull/425 */

      queue_cur->exec_cksum = 0;

      res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0);

      if (res == FAULT_ERROR) FATAL("Unable to execute target application");
    }

    if (stop_soon || res != crash_mode) {
      cur_skipped_paths++;
      goto abandon_entry;
    }
  }

  in_tree = json_to_tree(in_json);

  track = NULL;
  if (queue_cur->track_file) {
    track = parse_track_file(queue_cur->track_file);
  }

  struct_havoc_stage(argv, in_buf, len, in_tree, track);

  struct_aware_stage(argv, in_buf, len, in_tree, track);

  /************
   * TRIMMING *
   ************/

  if (!dumb_mode && !queue_cur->trim_done) {
    u8 res = trim_case(argv, queue_cur, in_buf, in_tree);

    if (res == FAULT_ERROR) FATAL("Unable to execute target application");

    if (stop_soon) {
      cur_skipped_paths++;
      goto abandon_entry;
    }

    /* Don't retry trimming, even if it failed. */

    queue_cur->trim_done = 1;

    if (len != queue_cur->len) len = queue_cur->len;
  }

  memcpy(out_buf, in_buf, len);
  out_tree = chunk_duplicate(in_tree, True);
  orig_tree = chunk_duplicate(in_tree, True);
  /*********************
   * PERFORMANCE SCORE *
   *********************/

  orig_perf = perf_score = calculate_score(queue_cur);

  /* Skip right away if -d is given, if we have done deterministic fuzzing on
     this entry ourselves (was_fuzzed), or if it has gone through deterministic
     testing in earlier, resumed runs (passed_det). */

  if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
    goto havoc_stage;

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance. */

  if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
    goto havoc_stage;

  doing_det = 1;

  list = get_node_list(in_tree);
  if (!list) {
    goto havoc_stage;
  }
  list = sortList(list);
  list_itr = list;
  while (1) {
    if (list_itr->next) {
      if (list_itr->next->start == list_itr->start) {
        list_temp = list_itr->next;
        list_itr->next = list_temp->next;
        ck_free(list_temp);
      } else {
        list_itr = list_itr->next;
      }
    } else {
      break;
    }
  }

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
  } while (0)

  /* Effector map setup. These macros calculate:

     EFF_APOS      - position of a particular file offset in the map.
     EFF_ALEN      - length of a map with a particular number of bytes.
     EFF_SPAN_ALEN - map span for a sequence of bytes.

   */

#define EFF_APOS(_p) ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x) ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l) (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l)-1) - EFF_APOS(_p) + 1)

  /* Initialize effector map for the next step (see comments below). Always
     flag first and last byte as doing something. */

  eff_map = ck_alloc(EFF_ALEN(len));
  eff_map[0] = 1;

  if (EFF_APOS(len - 1) != 0) {
    eff_map[EFF_APOS(len - 1)] = 1;
    eff_cnt++;
  }

  list_itr = list;
  while (list_itr != NULL) {
    start = list_itr->start;
    end = list_itr->end;
    field_len = end - start;
    /*********************************************
     * SIMPLE BITFLIP (+dictionary construction) *
     *********************************************/
    /* Single walking bit. */

    stage_short = "flip1";
    stage_max = end << 3;
    stage_name = "bitflip 1/1";

    stage_val_type = STAGE_VAL_NONE;

    orig_hit_cnt = queued_paths + unique_crashes;

    prev_cksum = queue_cur->exec_cksum;

    for (stage_cur = start << 3; stage_cur < stage_max; stage_cur++) {
      stage_cur_byte = stage_cur >> 3;

      FLIP_BIT(out_buf, stage_cur);

      if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
        goto abandon_entry;

      FLIP_BIT(out_buf, stage_cur);

      /* While flipping the least significant bit in every byte, pull of an
         extra trick to detect possible syntax tokens. In essence, the idea is
         that if you have a binary blob like this:

         xxxxxxxxIHDRxxxxxxxx

         ...and changing the leading and trailing bytes causes variable or no
         changes in program flow, but touching any character in the "IHDR"
         string always produces the same, distinctive path, it's highly likely
         that "IHDR" is an atomically-checked magic value of special
         significance to the fuzzed format.

         We do this here, rather than as a separate stage, because it's a nice
         way to keep the operation approximately "free" (i.e., no extra execs).

         Empirically, performing the check when flipping the least significant
         bit is advantageous, compared to doing it at the time of more
         disruptive changes, where the program flow may be affected in more
         violent ways.

         The caveat is that we won't generate dictionaries in the -d mode or -S
         mode - but that's probably a fair trade-off.

         This won't work particularly well with paths that exhibit variable
         behavior, but fails gracefully, so we'll carry out the checks anyway.

        */

      if (!dumb_mode && (stage_cur & 7) == 7) {
        u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

        if (stage_cur == stage_max - 1 && cksum == prev_cksum) {
          /* If at end of file and we are still collecting a string, grab the
             final character and force output. */

          if (a_len < MAX_AUTO_EXTRA)
            a_collect[a_len] = out_buf[stage_cur >> 3];
          a_len++;

          if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
            maybe_add_auto(a_collect, a_len);

        } else if (cksum != prev_cksum) {
          /* Otherwise, if the checksum has changed, see if we have something
             worthwhile queued up, and collect that if the answer is yes. */

          if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
            maybe_add_auto(a_collect, a_len);

          a_len = 0;
          prev_cksum = cksum;
        }

        /* Continue collecting string, but only if the bit flip actually made
           any difference - we don't want no-op tokens. */

        if (cksum != queue_cur->exec_cksum) {
          if (a_len < MAX_AUTO_EXTRA)
            a_collect[a_len] = out_buf[stage_cur >> 3];
          a_len++;
        }
      }
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP1] += field_len << 3;

    /* Two walking bits. */

    stage_name = "bitflip 2/1";
    stage_short = "flip2";
    stage_max = (end << 3) - 1;

    orig_hit_cnt = new_hit_cnt;

    for (stage_cur = start << 3; stage_cur < stage_max; stage_cur++) {
      stage_cur_byte = stage_cur >> 3;

      FLIP_BIT(out_buf, stage_cur);
      FLIP_BIT(out_buf, stage_cur + 1);

      if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
        goto abandon_entry;

      FLIP_BIT(out_buf, stage_cur);
      FLIP_BIT(out_buf, stage_cur + 1);
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP2] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP2] += (field_len << 3) - 1;

    /* Four walking bits. */

    stage_name = "bitflip 4/1";
    stage_short = "flip4";
    stage_max = (end << 3) - 3;

    orig_hit_cnt = new_hit_cnt;

    for (stage_cur = start << 3; stage_cur < stage_max; stage_cur++) {
      stage_cur_byte = stage_cur >> 3;

      FLIP_BIT(out_buf, stage_cur);
      FLIP_BIT(out_buf, stage_cur + 1);
      FLIP_BIT(out_buf, stage_cur + 2);
      FLIP_BIT(out_buf, stage_cur + 3);

      if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
        goto abandon_entry;

      FLIP_BIT(out_buf, stage_cur);
      FLIP_BIT(out_buf, stage_cur + 1);
      FLIP_BIT(out_buf, stage_cur + 2);
      FLIP_BIT(out_buf, stage_cur + 3);
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP4] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP4] += (field_len << 3) - 3;

    // /* Initialize effector map for the next step (see comments below). Always
    //    flag first and last byte as doing something. */

    // eff_map = ck_alloc(EFF_ALEN(len));
    // eff_map[0] = 1;

    // if (EFF_APOS(len - 1) != 0) {
    //   eff_map[EFF_APOS(len - 1)] = 1;
    //   eff_cnt++;
    // }

    /* Walking byte. */

    stage_name = "bitflip 8/8";
    stage_short = "flip8";
    stage_max = end;

    orig_hit_cnt = new_hit_cnt;

    for (stage_cur = start; stage_cur < stage_max; stage_cur++) {
      stage_cur_byte = stage_cur;

      out_buf[stage_cur] ^= 0xFF;

      if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
        goto abandon_entry;

      /* We also use this stage to pull off a simple trick: we identify
         bytes that seem to have no effect on the current execution path
         even when fully flipped - and we skip them during more expensive
         deterministic stages, such as arithmetics or known ints. */

      if (!eff_map[EFF_APOS(stage_cur)]) {
        u32 cksum;

        /* If in dumb mode or if the file is very short, just flag everything
           without wasting time on checksums. */

        if (!dumb_mode && len >= EFF_MIN_LEN)
          cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
        else
          cksum = ~queue_cur->exec_cksum;

        if (cksum != queue_cur->exec_cksum) {
          eff_map[EFF_APOS(stage_cur)] = 1;
          eff_cnt++;
        }
      }

      out_buf[stage_cur] ^= 0xFF;
    }

    /* If the effector map is more than EFF_MAX_PERC dense, just flag the
       whole thing as worth fuzzing, since we wouldn't be saving much time
       anyway. */

    if (eff_cnt != EFF_ALEN(len) &&
        eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {
      memset(eff_map, 1, EFF_ALEN(len));

      blocks_eff_select += EFF_ALEN(len);

    } else {
      blocks_eff_select += eff_cnt;
    }

    blocks_eff_total += EFF_ALEN(len);

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP8] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP8] += field_len;

    /* Two walking bytes. */

    if (field_len < 2) goto skip_bitflip;

    stage_name = "bitflip 16/8";
    stage_short = "flip16";
    stage_cur = start;
    stage_max = field_len - 1;

    orig_hit_cnt = new_hit_cnt;

    for (i = start; i < end - 1; i++) {
      /* Let's consult the effector map... */

      if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
        stage_max--;
        continue;
      }

      stage_cur_byte = i;

      *(u16 *)(out_buf + i) ^= 0xFFFF;

      if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
        goto abandon_entry;
      stage_cur++;

      *(u16 *)(out_buf + i) ^= 0xFFFF;
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP16] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP16] += stage_max;

    if (field_len < 4) goto skip_bitflip;

    /* Four walking bytes. */

    stage_name = "bitflip 32/8";
    stage_short = "flip32";
    stage_cur = start;
    stage_max = end - 3;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < end - 3; i++) {
      /* Let's consult the effector map... */
      if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
          !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
        stage_max--;
        continue;
      }

      stage_cur_byte = i;

      *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;

      if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
        goto abandon_entry;
      stage_cur++;

      *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP32] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP32] += stage_max;

  skip_bitflip:

    if (no_arith) goto skip_arith;

    /**********************
     * ARITHMETIC INC/DEC *
     **********************/

    /* 8-bit arithmetics. */

    stage_name = "arith 8/8";
    stage_short = "arith8";
    stage_cur = start;
    stage_max = 2 * field_len * ARITH_MAX;

    stage_val_type = STAGE_VAL_LE;

    orig_hit_cnt = new_hit_cnt;

    for (i = start; i < end; i++) {
      u8 orig = out_buf[i];

      /* Let's consult the effector map... */

      if (!eff_map[EFF_APOS(i)]) {
        stage_max -= 2 * ARITH_MAX;
        continue;
      }

      stage_cur_byte = i;

      for (j = 1; j <= ARITH_MAX; j++) {
        u8 r = orig ^ (orig + j);

        /* Do arithmetic operations only if the result couldn't be a product
           of a bitflip. */

        if (!could_be_bitflip(r)) {
          stage_cur_val = j;
          out_buf[i] = orig + j;  // no change of file format

          if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
            goto abandon_entry;
          stage_cur++;

        } else
          stage_max--;

        r = orig ^ (orig - j);

        if (!could_be_bitflip(r)) {
          stage_cur_val = -j;
          out_buf[i] = orig - j;  // no change of file format

          if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
            goto abandon_entry;
          stage_cur++;

        } else
          stage_max--;

        out_buf[i] = orig;
      }
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_ARITH8] += stage_max;

    /* 16-bit arithmetics, both endians. */

    if (field_len < 2) goto skip_arith;

    stage_name = "arith 16/8";
    stage_short = "arith16";
    stage_cur = start;
    stage_max = 4 * (field_len - 1) * ARITH_MAX;

    orig_hit_cnt = new_hit_cnt;

    for (i = start; i < end - 1; i++) {
      u16 orig = *(u16 *)(out_buf + i);

      /* Let's consult the effector map... */

      if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
        stage_max -= 4 * ARITH_MAX;
        continue;
      }

      stage_cur_byte = i;

      for (j = 1; j <= ARITH_MAX; j++) {
        u16 r1 = orig ^ (orig + j), r2 = orig ^ (orig - j),
            r3 = orig ^ SWAP16(SWAP16(orig) + j),
            r4 = orig ^ SWAP16(SWAP16(orig) - j);

        /* Try little endian addition and subtraction first. Do it only
           if the operation would affect more than one byte (hence the
           & 0xff overflow checks) and if it couldn't be a product of
           a bitflip. */

        stage_val_type = STAGE_VAL_LE;

        if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {
          stage_cur_val = j;
          *(u16 *)(out_buf + i) = orig + j;

          if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
            goto abandon_entry;
          stage_cur++;

        } else
          stage_max--;

        if ((orig & 0xff) < j && !could_be_bitflip(r2)) {
          stage_cur_val = -j;
          *(u16 *)(out_buf + i) = orig - j;

          if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
            goto abandon_entry;
          stage_cur++;

        } else
          stage_max--;

        /* Big endian comes next. Same deal. */

        stage_val_type = STAGE_VAL_BE;

        if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {
          stage_cur_val = j;
          *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) + j);

          if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
            goto abandon_entry;
          stage_cur++;

        } else
          stage_max--;

        if ((orig >> 8) < j && !could_be_bitflip(r4)) {
          stage_cur_val = -j;
          *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) - j);

          if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
            goto abandon_entry;
          stage_cur++;

        } else
          stage_max--;

        *(u16 *)(out_buf + i) = orig;
      }
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_ARITH16] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_ARITH16] += stage_max;

    /* 32-bit arithmetics, both endians. */

    if (field_len < 4) goto skip_arith;

    stage_name = "arith 32/8";
    stage_short = "arith32";
    stage_cur = start;
    stage_max = 4 * (field_len - 3) * ARITH_MAX;

    orig_hit_cnt = new_hit_cnt;

    for (i = start; i < end - 3; i++) {
      u32 orig = *(u32 *)(out_buf + i);

      /* Let's consult the effector map... */

      if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
          !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
        stage_max -= 4 * ARITH_MAX;
        continue;
      }

      stage_cur_byte = i;

      for (j = 1; j <= ARITH_MAX; j++) {
        u32 r1 = orig ^ (orig + j), r2 = orig ^ (orig - j),
            r3 = orig ^ SWAP32(SWAP32(orig) + j),
            r4 = orig ^ SWAP32(SWAP32(orig) - j);

        /* Little endian first. Same deal as with 16-bit: we only want to
           try if the operation would have effect on more than two bytes. */

        stage_val_type = STAGE_VAL_LE;

        if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {
          stage_cur_val = j;
          *(u32 *)(out_buf + i) = orig + j;

          if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
            goto abandon_entry;
          stage_cur++;

        } else
          stage_max--;

        if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {
          stage_cur_val = -j;
          *(u32 *)(out_buf + i) = orig - j;

          if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
            goto abandon_entry;
          stage_cur++;

        } else
          stage_max--;

        /* Big endian next. */

        stage_val_type = STAGE_VAL_BE;

        if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {
          stage_cur_val = j;
          *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) + j);

          if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
            goto abandon_entry;
          stage_cur++;

        } else
          stage_max--;

        if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {
          stage_cur_val = -j;
          *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) - j);

          if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
            goto abandon_entry;
          stage_cur++;

        } else
          stage_max--;

        *(u32 *)(out_buf + i) = orig;
      }
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_ARITH32] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_ARITH32] += stage_max;

  skip_arith:

    /**********************
     * INTERESTING VALUES *
     **********************/

    stage_name = "interest 8/8";
    stage_short = "int8";
    stage_cur = start;
    stage_max = field_len * sizeof(interesting_8);

    stage_val_type = STAGE_VAL_LE;

    orig_hit_cnt = new_hit_cnt;

    /* Setting 8-bit integers. */

    for (i = start; i < end; i++) {
      u8 orig = out_buf[i];

      /* Let's consult the effector map... */

      if (!eff_map[EFF_APOS(i)]) {
        stage_max -= sizeof(interesting_8);
        continue;
      }

      stage_cur_byte = i;

      for (j = 0; j < sizeof(interesting_8); j++) {
        /* Skip if the value could be a product of bitflips or arithmetics. */

        if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
            could_be_arith(orig, (u8)interesting_8[j], 1)) {
          stage_max--;
          continue;
        }

        stage_cur_val = interesting_8[j];
        out_buf[i] = interesting_8[j];  // no change of file format

        if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
          goto abandon_entry;

        out_buf[i] = orig;
        stage_cur++;
      }
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_INTEREST8] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_INTEREST8] += stage_max;

    /* Setting 16-bit integers, both endians. */

    if (no_arith || field_len < 2) goto skip_interest;

    stage_name = "interest 16/8";
    stage_short = "int16";
    stage_cur = 0;
    stage_max = 2 * (field_len - 1) * (sizeof(interesting_16) >> 1);

    orig_hit_cnt = new_hit_cnt;

    for (i = start; i < end - 1; i++) {
      u16 orig = *(u16 *)(out_buf + i);

      /* Let's consult the effector map... */

      if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
        stage_max -= sizeof(interesting_16);
        continue;
      }

      stage_cur_byte = i;

      for (j = 0; j < sizeof(interesting_16) / 2; j++) {
        stage_cur_val = interesting_16[j];

        /* Skip if this could be a product of a bitflip, arithmetics,
           or single-byte interesting value insertion. */

        if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
            !could_be_arith(orig, (u16)interesting_16[j], 2) &&
            !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {
          stage_val_type = STAGE_VAL_LE;

          *(u16 *)(out_buf + i) = interesting_16[j];

          if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
            goto abandon_entry;
          stage_cur++;

        } else
          stage_max--;

        if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
            !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
            !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
            !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {
          stage_val_type = STAGE_VAL_BE;

          *(u16 *)(out_buf + i) = SWAP16(interesting_16[j]);
          if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
            goto abandon_entry;
          stage_cur++;

        } else
          stage_max--;
      }

      *(u16 *)(out_buf + i) = orig;
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_INTEREST16] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_INTEREST16] += stage_max;

    if (field_len < 4) goto skip_interest;

    /* Setting 32-bit integers, both endians. */

    stage_name = "interest 32/8";
    stage_short = "int32";
    stage_cur = 0;
    stage_max = 2 * (field_len - 3) * (sizeof(interesting_32) >> 2);

    orig_hit_cnt = new_hit_cnt;

    for (i = start; i < end - 3; i++) {
      u32 orig = *(u32 *)(out_buf + i);

      /* Let's consult the effector map... */

      if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
          !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
        stage_max -= sizeof(interesting_32) >> 1;
        continue;
      }

      stage_cur_byte = i;

      for (j = 0; j < sizeof(interesting_32) / 4; j++) {
        stage_cur_val = interesting_32[j];

        /* Skip if this could be a product of a bitflip, arithmetics,
           or word interesting value insertion. */

        if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
            !could_be_arith(orig, interesting_32[j], 4) &&
            !could_be_interest(orig, interesting_32[j], 4, 0)) {
          stage_val_type = STAGE_VAL_LE;

          *(u32 *)(out_buf + i) = interesting_32[j];

          if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
            goto abandon_entry;
          stage_cur++;

        } else
          stage_max--;

        if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
            !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
            !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
            !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {
          stage_val_type = STAGE_VAL_BE;

          *(u32 *)(out_buf + i) = SWAP32(interesting_32[j]);
          if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
            goto abandon_entry;
          stage_cur++;

        } else
          stage_max--;
      }

      *(u32 *)(out_buf + i) = orig;
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_INTEREST32] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_INTEREST32] += stage_max;

  skip_interest:
    /********************
     * DICTIONARY STUFF *
     ********************/

    if (!extras_cnt) goto skip_user_extras;
    /* Overwrite with user-supplied extras. */

    stage_name = "user extras (over)";
    stage_short = "ext_UO";
    stage_cur = start;
    stage_max = extras_cnt * field_len;

    stage_val_type = STAGE_VAL_NONE;

    orig_hit_cnt = new_hit_cnt;

    for (i = start; i < end; i++) {
      u32 last_len = 0;

      stage_cur_byte = i;

      /* Extras are sorted by size, from smallest to largest. This means
         that we don't have to worry about restoring the buffer in
         between writes at a particular offset determined by the outer
         loop. */

      for (j = 0; j < extras_cnt; j++) {
        /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
           skip them if there's no room to insert the payload, if the token
           is redundant, or if its entire span has no bytes set in the effector
           map. */

        if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
            extras[j].len > end - i ||
            !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
            !memchr(eff_map + EFF_APOS(i), 1,
                    EFF_SPAN_ALEN(i, extras[j].len))) {
          stage_max--;
          continue;
        }

        last_len = extras[j].len;
        memcpy(out_buf + i, extras[j].data, last_len);  // no change of file
                                                        // format

        if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
          goto abandon_entry;

        stage_cur++;
      }

      /* Restore all the clobbered memory. */
      memcpy(out_buf + i, in_buf + i, last_len);
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_EXTRAS_UO] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_EXTRAS_UO] += stage_max;

    /* Insertion of user-supplied extras. */

    stage_name = "user extras (insert)";
    stage_short = "ext_UI";
    stage_cur = start;
    stage_max = extras_cnt * (field_len + 1);

    orig_hit_cnt = new_hit_cnt;

    ex_tmp = ck_alloc(len + MAX_DICT_FILE);

    for (i = start; i <= end; i++) {
      stage_cur_byte = i;

      for (j = 0; j < extras_cnt; j++) {
        if (len + extras[j].len > MAX_FILE) {
          stage_max--;
          continue;
        }

        /* Insert token */
        memcpy(ex_tmp + i, extras[j].data, extras[j].len);

        /* Copy tail */
        memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);

        /* Update format file */
        insert_block(out_tree, i, extras[j].len);

        if (common_fuzz_stuff(argv, ex_tmp, len + extras[j].len, out_tree,
                              NULL)) {
          ck_free(ex_tmp);
          goto abandon_entry;
        }
        stage_cur++;
        free_tree(out_tree, True);
        // out_json = cJSON_Duplicate(in_json, 1);
        out_tree = chunk_duplicate(in_tree, True);
      }

      /* Copy head */
      ex_tmp[i] = out_buf[i];
    }
    free_tree(out_tree, True);
    out_tree = chunk_duplicate(in_tree, 1);

    ck_free(ex_tmp);

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_EXTRAS_UI] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_EXTRAS_UI] += stage_max;

  skip_user_extras:

    if (!a_extras_cnt) goto skip_extras;

    stage_name = "auto extras (over)";
    stage_short = "ext_AO";
    stage_cur = start;
    stage_max = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * field_len;

    stage_val_type = STAGE_VAL_NONE;

    orig_hit_cnt = new_hit_cnt;

    for (i = start; i < end; i++) {
      u32 last_len = 0;

      stage_cur_byte = i;

      for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++) {
        /* See the comment in the earlier code; extras are sorted by size. */

        if (a_extras[j].len > end - i ||
            !memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
            !memchr(eff_map + EFF_APOS(i), 1,
                    EFF_SPAN_ALEN(i, a_extras[j].len))) {
          stage_max--;
          continue;
        }

        last_len = a_extras[j].len;
        memcpy(out_buf + i, a_extras[j].data,
               last_len);  // no change of file format

        if (common_fuzz_stuff(argv, out_buf, len, out_tree, NULL))
          goto abandon_entry;

        stage_cur++;
      }

      /* Restore all the clobbered memory. */
      memcpy(out_buf + i, in_buf + i, last_len);
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_EXTRAS_AO] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_EXTRAS_AO] += stage_max;

  skip_extras:

    list_itr = list_itr->next;
  }

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're properly done with deterministic steps and can mark it as such
     in the .state/ directory. */

  if (!queue_cur->passed_det) mark_as_det_done(queue_cur);

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

  stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {
    stage_name = "havoc";
    stage_short = "havoc";
    stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) * perf_score /
                havoc_div / 100;

  } else {
    static u8 tmp[32];

    perf_score = orig_perf;

    sprintf(tmp, "splice %u", splice_cycle);
    stage_name = tmp;
    stage_short = "splice";
    stage_max = SPLICE_HAVOC * perf_score / havoc_div / 100;
  }

  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;

  temp_len = len;

  orig_hit_cnt = queued_paths + unique_crashes;

  havoc_queued = queued_paths;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

    stage_cur_val = use_stacking;

    for (i = 0; i < use_stacking; i++) {
      u32 num = UR(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0));

      switch (num) {
        case 0:

          /* Flip a single bit somewhere. Spooky! */

          FLIP_BIT(out_buf, UR(temp_len << 3));
          break;

        case 1:

          /* Set byte to interesting value. */

          out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];
          break;

        case 2:

          /* Set word to interesting value, randomly choosing endian. */

          if (temp_len < 2) break;

          if (UR(2)) {
            *(u16 *)(out_buf + UR(temp_len - 1)) =
                interesting_16[UR(sizeof(interesting_16) >> 1)];

          } else {
            *(u16 *)(out_buf + UR(temp_len - 1)) =
                SWAP16(interesting_16[UR(sizeof(interesting_16) >> 1)]);
          }

          break;

        case 3:

          /* Set dword to interesting value, randomly choosing endian. */

          if (temp_len < 4) break;

          if (UR(2)) {
            *(u32 *)(out_buf + UR(temp_len - 3)) =
                interesting_32[UR(sizeof(interesting_32) >> 2)];

          } else {
            *(u32 *)(out_buf + UR(temp_len - 3)) =
                SWAP32(interesting_32[UR(sizeof(interesting_32) >> 2)]);
          }

          break;

        case 4:

          /* Randomly subtract from byte. */

          out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
          break;

        case 5:

          /* Randomly add to byte. */

          out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
          break;

        case 6:

          /* Randomly subtract from word, random endian. */

          if (temp_len < 2) break;

          if (UR(2)) {
            u32 pos = UR(temp_len - 1);

            *(u16 *)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {
            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16 *)(out_buf + pos) =
                SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);
          }

          break;

        case 7:

          /* Randomly add to word, random endian. */

          if (temp_len < 2) break;

          if (UR(2)) {
            u32 pos = UR(temp_len - 1);

            *(u16 *)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {
            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16 *)(out_buf + pos) =
                SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);
          }

          break;

        case 8:

          /* Randomly subtract from dword, random endian. */

          if (temp_len < 4) break;

          if (UR(2)) {
            u32 pos = UR(temp_len - 3);

            *(u32 *)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {
            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32 *)(out_buf + pos) =
                SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);
          }

          break;

        case 9:

          /* Randomly add to dword, random endian. */

          if (temp_len < 4) break;

          if (UR(2)) {
            u32 pos = UR(temp_len - 3);

            *(u32 *)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {
            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32 *)(out_buf + pos) =
                SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);
          }

          break;

        case 10:

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          out_buf[UR(temp_len)] ^= 1 + UR(255);
          break;

        case 11 ... 12: {
          /* Delete bytes. We're making this a bit more likely
             than insertion (the next option) in hopes of keeping
             files reasonably small. */
          u32 del_from, del_len;

          if (temp_len < 2) break;

          /* Don't delete too much. */

          del_len = choose_block_len(temp_len - 1);

          del_from = UR(temp_len - del_len + 1);

          memmove(out_buf + del_from, out_buf + del_from + del_len,
                  temp_len - del_from - del_len);
          temp_len -= del_len;

          /* Update format file */
          delete_block(out_tree, NULL, del_from, del_len);
          break;
        }

        case 13:

          if (temp_len + HAVOC_BLK_XL < MAX_FILE) {
            /* Clone bytes (75%) or insert a block of constant bytes (25%). */

            u8 actually_clone = UR(4);
            u32 clone_from, clone_to, clone_len;
            u8 *new_buf;

            if (actually_clone) {
              clone_len = choose_block_len(temp_len);
              clone_from = UR(temp_len - clone_len + 1);

            } else {
              clone_len = choose_block_len(HAVOC_BLK_XL);
              clone_from = 0;
            }

            clone_to = UR(temp_len);

            new_buf = ck_alloc_nozero(temp_len + clone_len);

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            if (actually_clone)
              memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
            else
              memset(new_buf + clone_to,
                     UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            ck_free(out_buf);
            out_buf = new_buf;
            temp_len += clone_len;

            /* Update format file */
            insert_block(out_tree, clone_from, clone_len);
          }

          break;

        case 14: {
          /* Overwrite bytes with a randomly selected chunk (75%) or fixed
             bytes (25%). */

          u32 copy_from, copy_to, copy_len;

          if (temp_len < 2) break;

          copy_len = choose_block_len(temp_len - 1);

          copy_from = UR(temp_len - copy_len + 1);
          copy_to = UR(temp_len - copy_len + 1);

          if (UR(4)) {
            if (copy_from != copy_to)
              memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

          } else
            memset(out_buf + copy_to, UR(2) ? UR(256) : out_buf[UR(temp_len)],
                   copy_len);

          break;
        }

        case 15: {
          /* Overwrite bytes with an extra. */

          if (!extras_cnt || (a_extras_cnt && UR(2))) {
            /* No user-specified extras or odds in our favor. Let's use an
               auto-detected one. */

            u32 use_extra = UR(a_extras_cnt);
            u32 extra_len = a_extras[use_extra].len;
            u32 insert_at;

            if (extra_len > temp_len) break;

            insert_at = UR(temp_len - extra_len + 1);
            memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);

          } else {
            /* No auto extras or odds in our favor. Use the dictionary. */

            u32 use_extra = UR(extras_cnt);
            u32 extra_len = extras[use_extra].len;
            u32 insert_at;

            if (extra_len > temp_len) break;

            insert_at = UR(temp_len - extra_len + 1);
            memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);
          }

          break;
        }

        case 16: {
          u32 use_extra, extra_len, insert_at = UR(temp_len + 1);
          u8 *new_buf;

          /* Insert an extra. Do the same dice-rolling stuff as for the
             previous case. */

          if (!extras_cnt || (a_extras_cnt && UR(2))) {
            use_extra = UR(a_extras_cnt);
            extra_len = a_extras[use_extra].len;

            if (temp_len + extra_len >= MAX_FILE) break;

            new_buf = ck_alloc_nozero(temp_len + extra_len);

            /* Head */
            memcpy(new_buf, out_buf, insert_at);

            /* Inserted part */
            memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);

          } else {
            use_extra = UR(extras_cnt);
            extra_len = extras[use_extra].len;

            if (temp_len + extra_len >= MAX_FILE) break;

            new_buf = ck_alloc_nozero(temp_len + extra_len);

            /* Head */
            memcpy(new_buf, out_buf, insert_at);

            /* Inserted part */
            memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);
          }

          /* Tail */
          memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
                 temp_len - insert_at);

          ck_free(out_buf);
          out_buf = new_buf;
          temp_len += extra_len;

          /* Update format file */
          insert_block(out_tree, insert_at, extra_len);
          break;
        }
      }
    }

    if (common_fuzz_stuff(argv, out_buf, temp_len, out_tree, track))
      goto abandon_entry;

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    if (temp_len < len) {
      out_buf = ck_realloc(out_buf, len);
    }
    temp_len = len;
    memcpy(out_buf, in_buf, len);
    // cJSON_Delete(out_json);
    // out_json = cJSON_Duplicate(in_json, 1);
    free_tree(out_tree, True);
    out_tree = chunk_duplicate(in_tree, 1);

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */

    if (queued_paths != havoc_queued) {
      if (perf_score <= HAVOC_MAX_MULT * 100) {
        stage_max *= 2;
        perf_score *= 2;
      }

      havoc_queued = queued_paths;
    }
  }

  new_hit_cnt = queued_paths + unique_crashes;

  if (!splice_cycle) {
    stage_finds[STAGE_HAVOC] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_HAVOC] += stage_max;
  } else {
    stage_finds[STAGE_SPLICE] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_SPLICE] += stage_max;
  }

#ifndef IGNORE_FINDS

  /************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. */

retry_splicing:

  if (use_splicing && splice_cycle++ < SPLICE_CYCLES && queued_paths > 1 &&
      queue_cur->len > 1) {
    struct queue_entry *target;
    u32 tid, split_at;
    u8 *new_buf;
    s32 f_diff, l_diff;
    cJSON *target_json;
    Chunk *target_tree;

    /* First of all, if we've modified in_buf for havoc, let's clean that
       up... */

    if (in_buf != orig_in) {
      ck_free(in_buf);
      in_buf = orig_in;
      len = queue_cur->len;
      free_tree(in_tree, True);
      in_tree = chunk_duplicate(orig_tree, True);
    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */

    do {
      tid = UR(queued_paths);
    } while (tid == current_entry);

    splicing_with = tid;
    target = queue;

    while (tid >= 100) {
      target = target->next_100;
      tid -= 100;
    }
    while (tid--) target = target->next;

    /* Make sure that the target has a reasonable length. */

    while (target && (target->len < 2 || target == queue_cur)) {
      target = target->next;
      splicing_with++;
    }

    if (!target) goto retry_splicing;

    /* Read the testcase into a new buffer. */

    fd = open(target->fname, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

    new_buf = ck_alloc_nozero(target->len);

    ck_read(fd, new_buf, target->len, target->fname);

    close(fd);

    /* Parse the format file of the testcase */

    target_json = parse_json(target->format_file);
    target_tree = json_to_tree(target_json);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */

    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
      ck_free(new_buf);
      cJSON_Delete(target_json);
      free_tree(target_tree, True);
      goto retry_splicing;
    }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + UR(l_diff - f_diff);

    /* Do the thing. */

    len = target->len;
    memcpy(new_buf, in_buf, split_at);
    in_buf = new_buf;

    ck_free(out_buf);
    out_buf = ck_alloc(len);
    memcpy(out_buf, in_buf, len);

    /* Update the format file. */
    in_tree = splice_tree(in_tree, target_tree, split_at);
    out_tree = chunk_duplicate(in_tree, True);
    goto havoc_stage;
  }

#endif /* !IGNORE_FINDS */

  ret_val = 0;

abandon_entry:

  splicing_with = -1;

  /* Update pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!stop_soon && !queue_cur->cal_failed && !queue_cur->was_fuzzed) {
    queue_cur->was_fuzzed = 1;
    pending_not_fuzzed--;
    if (queue_cur->favored) pending_favored--;
  }

  munmap(orig_in, queue_cur->len);

  if (in_buf != orig_in) ck_free(in_buf);
  ck_free(out_buf);
  ck_free(eff_map);

  cJSON_Delete(in_json);

  free_node_list(list);
  free_tree(in_tree, True);
  free_tree(out_tree, True);

  free_track(track);

  return ret_val;

#undef FLIP_BIT
}