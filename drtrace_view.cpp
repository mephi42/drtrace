#define _LARGEFILE64_SOURCE
#define TRACE_FILE "./trace.out"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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
  operator void*() { return value_; }

  template<typename T>
  operator T*() { return (T*)value_; }
};

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
  for(struct tlv_t* tlv = (tlv_t*)p;
      tlv < last;
      previous_tlv = tlv,
      tlv = (struct tlv_t*)((char*)tlv + tlv->length),
      tlv_count++) {
    switch(tlv->type) {
    case TYPE_BB:
      break;
    case TYPE_TRACE:
      break;
    default:
      fprintf(stderr,
              "fatal: unexpected TLV type at offset 0x%tx: 0x%zx\n",
              (char*)tlv - (char*)p,
              (size_t)tlv->type);
      if(previous_tlv) {
        fprintf(stderr,
                "info: previous TLV is at offset 0x%zx\n",
                (char*)previous_tlv - (char*)p);
      } else {
        fprintf(stderr, "info: there is no previous TLV\n");
      }
      return 1;
    }
  }
  fprintf(stderr, "info: tlv count = %zu\n", tlv_count);

  return 0;
}
