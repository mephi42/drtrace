#define _LARGEFILE64_SOURCE
#define TRACE_FILE "./trace.out"

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>

#include "drtrace.h"

class fd_t {
  int value_;
public:
  fd_t(int value) : value_(value) {}
  ~fd_t() {
    if(value_ != -1 && close(value_) == -1) {
      perror("warning: close() failed");
    }
  }
  operator int() { return value_; }
};

class mmap_t {
  void* value_;
  size_t size_;
public:
  mmap_t(void* value, size_t size) : value_(value), size_(size) {}
  ~mmap_t() {
    if(value_ != MAP_FAILED && munmap(value_, size_) == -1) {
      perror("warning: munmap() failed");
    }
  }

  template<typename T>
  operator T*() { return (T*)value_; }
};

void dump(void* p, size_t size) {
  if(size == 0) { return; }
  fprintf(stderr, "%.2x", ((unsigned char*)p)[0]);
  for(size_t i = 1; i < size; i++) {
    fprintf(stderr, " %.2x", ((unsigned char*)p)[i]);
  }
  fprintf(stderr, "\n");
}

#define container_of(ptr, type, member) \
    ((type*)((char*)(ptr) - offsetof(type, member)))

size_t code_size(struct bb_t* bb) {
  struct tlv_t* tlv = container_of(bb, struct tlv_t, value);
  return tlv->length - ((char*)bb->code - (char*)tlv);
}

void dump_code(struct bb_t* bb) {
  dump(bb->code, code_size(bb));
}

int main() {
  fd_t fd(open(TRACE_FILE, O_RDONLY | O_LARGEFILE));
  if(fd == -1) {
    perror("fatal: open() failed");
    return 1;
  }

  struct stat s;
  int stat_rc = fstat(fd, &s);
  if(stat_rc == -1) {
    perror("fatal: stat() failed");
    return 1;
  }
  size_t size = s.st_size;
  fprintf(stderr, "info: size = %zu\n", size);

  mmap_t p(mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0), size);
  if(p == MAP_FAILED) {
    perror("fatal: mmap() failed");
    return 1;
  }

  struct tlv_t* previous_tlv = NULL;
  void* last = (char*)p + size;
  size_t tlv_count = 0;
  std::unordered_map<uintptr_t, struct bb_t*> bbs;
  for(struct tlv_t* tlv = (tlv_t*)p;
      tlv < last;
      previous_tlv = tlv,
      tlv = (struct tlv_t*)((char*)tlv + tlv->length),
      tlv_count++) {
    switch(tlv->type) {
    case TYPE_BB: {
      bb_t* bb = (bb_t*)tlv->value;
      bbs[bb->id] = bb;
      break;
    }
    case TYPE_TRACE:
      break;
    default:
      fprintf(stderr,
              "fatal: unexpected TLV type at offset 0x%tx: 0x%zx\n",
              (char*)tlv - (char*)p,
              (size_t)tlv->type);
      if(previous_tlv) {
        fprintf(stderr,
                "info: previous TLV is at offset 0x%tx\n",
                (char*)previous_tlv - (char*)p);
      } else {
        fprintf(stderr, "info: there is no previous TLV\n");
      }
      return 1;
    }
  }
  fprintf(stderr, "info: tlv count = %zu\n", tlv_count);
  fprintf(stderr, "info: bb count = %zu\n", bbs.size());

  return 0;
}
