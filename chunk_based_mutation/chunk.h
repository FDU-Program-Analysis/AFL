#ifndef __CHUNK_H__
#define __CHUNK_H__

#include <stdint.h>

typedef enum {
  length_meta,
  length_payload,
  offset_meta,
  offset_payload
} LEN_OFF;

typedef struct {
  struct Chunk *ptr;
  LEN_OFF type;
  uint32_t k;
  uint32_t b; // if type <=1, length=kx+b;if type > 1 (offset),b is meaningless
  struct Cons *next;
} Cons;

typedef struct Chunk {
  uint32_t start;
  uint32_t end;
  uint8_t *id;
  uint8_t *type;
  struct Chunk *next;
  struct Chunk *prev;
  struct Chunk *son;
  struct Chunk *father;
  struct Cons *cons;
} Chunk;

typedef struct Scope {
  struct Chunk *chunk;
  uint32_t start;
  uint32_t end;
  struct Scope *next;
} Scope;

#endif  // !__CHUNK_H__