#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

char data[100];
unsigned int unread_marker = 0;
int saw_SOI = 0;
char *cinfo;

typedef enum
{
  M_SOI = 0xd8,
  M_EOI = 0xd9,
  M_SOS = 0xda,
  M_DQT = 0xdb,

  M_APP0 = 0xe0,

  M_FAKE = 0xa0,

  M_ERROR = 0x100
} JPEG_MARKER;

int first_marker()
{ 
  int c = 0, c2 = 0;
  memcpy(&c, cinfo++, 1);
  memcpy(&c2, cinfo++, 1);
  if (c != 0xFF || c2 != (int)M_SOI)
  {
    printf("ERROR SOI MARKER!\n");
    assert(0 && 3);
    return 0;
  }
  unread_marker = c2;
  return 1;
}

int next_marker()
{ 
  int c = 0;
  for (;;)
  { 
    memcpy(&c, cinfo++, 1);
    while (c != 0xFF)
    { 
      memcpy(&c, cinfo++, 1);
    }
    memcpy(&c, cinfo++, 1);
    if (c != 0)
      break;
  }
  unread_marker = c;
  return 1;
}

int get_soi()
{ 
  if (!saw_SOI) {
    saw_SOI = 1;
    return 1;
  }
  else {
    //duplicate SOI
    assert(0 && 1);
    return 0;
  }
  return 0;
}

int hex2int(char *len_tmp)
{
  int len = 0;
  len = len_tmp[0]*16*16 + len_tmp[1];
  return len;
}

int get_chunk()
{
  char len_tmp[3];
  int len = 0;
  memcpy(len_tmp, cinfo, 2);
  // printf("%02x %02x\n", len_tmp[0], len_tmp[1]);
  len = hex2int(len_tmp);
  // memcpy(&len, cinfo + 1, 1);
  cinfo += 2;
  len -= 2;
  while (len > 0)
  {
    char c = *cinfo++;
    printf("%02x ", c);
    len--;
    ///len abort
  }
  printf("\n");
  return 1;
}

int read_markers()
{
  for (;;)
  { 
    if (unread_marker == 0)
    {
      if (!saw_SOI)
      {
        if (!first_marker())
          return -1;
      }
      else
      {
        if (!next_marker())
          return -1;
      }
    }

    switch (unread_marker)
    {
    case M_SOI:
      if (!get_soi())
        return -1;
      break;
    case M_EOI:
      printf("EOI\n");
      unread_marker = 0; /* processed the marker */
      return -1;
    case M_DQT:
      if (!get_chunk())
        return -1;
      break;
    case M_APP0:
      if (!get_chunk())
        return -1;
      break;
    case M_FAKE: 
      assert(0 && 2);
    default: /* must be DHP, EXP, JPGn, or RESn */
      printf("ERROR MARKER!\n");
    }
    /* Successfully processed marker, so reset state variable */
    unread_marker = 0;
  } /* end loop */
  //unread_marker assert
}

int main(int argc, char **argv)
{
  if (argc != 2) {
    printf("usage: duplicate_chunk <input_file_name>\n");
    return -1;
  }
  FILE *fp;
  fp = fopen(argv[1], "rb");
  if (fp)
  {
    //size = 55 byte(EOF);
    fread(data, sizeof(char), 55, fp);
    cinfo = data;
    read_markers();
  }

  return 0;
}

