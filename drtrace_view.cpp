#define _LARGEFILE64_SOURCE
#define __STDC_FORMAT_MACROS
#define TRACE_FILE "./trace.out"

#include <dr_api.h>
#include <fcntl.h>
#include <inttypes.h>
#include <list>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>

#include "crc32.h"
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

void dump_code(struct frag_t* frag) {
  struct tlv_t* tlv = container_of(frag, struct tlv_t, value);
  void* end = (char*)tlv + tlv->length;
  for(struct code_chunk_t* chunk = (struct code_chunk_t*)frag->chunks;
      chunk < end;
      chunk = (struct code_chunk_t*)&chunk->code[chunk->size]) {
    instr_t instr;
    instr_init(GLOBAL_DCONTEXT, &instr);
    for(size_t offset = 0; offset < chunk->size; ) {
      drtrace_uintptr_t pc = chunk->pc + offset;
      fprintf(stderr, DRTRACE_UINTPTR_FMT ": ", pc);
      instr_reset(GLOBAL_DCONTEXT, &instr);
      byte* next = decode_from_copy(GLOBAL_DCONTEXT,
                                    &chunk->code[offset],
                                    (byte*)(uintptr_t)pc,
                                    &instr);
      if(next == NULL) {
        fprintf(stderr, "???\n");
        break;
      }
      char buf[256];
      instr_disassemble_to_buffer(GLOBAL_DCONTEXT, &instr, buf, sizeof(buf));
      fprintf(stderr, "%s\n", buf);
      offset = next - &chunk->code[0];
    }
    instr_free(GLOBAL_DCONTEXT, &instr);
  }
}

size_t trace_count(struct trace_t* trace) {
  struct tlv_t* tlv = container_of(trace, struct tlv_t, value);
  size_t bytes = tlv->length - ((char*)trace->frag_id - (char*)tlv);
  return bytes / sizeof(trace->frag_id[0]);
}

struct frag_entry_t {
  struct frag_t* frag;
};

int main(int argc, char** argv) {
  frag_id_t track_frag = -1;
  for(int i = 1; i < argc; i++) {
    char* arg = argv[i];
    if(strcmp(arg, "--track-frag") == 0) {
      i++;
      if(i >= argc) {
        fprintf(stderr, "fatal: missing --track-frag value\n");
        return 1;
      }
      sscanf(argv[i], FRAG_ID_FMT, &track_frag);
      fprintf(stderr, "info: tracking frag " FRAG_ID_FMT "\n", track_frag);
    }
  }

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

  int rc = 0;
  void* trace_end = (char*)p + size;
  size_t block_count = 0;
  size_t tlv_count = 0;
  std::unordered_map<frag_id_t, frag_entry_t> frags;
  size_t frags_executed = 0;
  for(struct block_t* block = (struct block_t*)p;
      block < trace_end && rc == 0;
      block = aligned_block((char*)block + block->length),
      block_count++) {
    // Validate block length.
    void* block_end = (char*)block + block->length;
    if(block_end < (char*)block + sizeof(struct block_t) ||
       block_end > trace_end) {
      fprintf(stderr,
              "fatal: invalid block at offset 0x%tx of length 0x%x\n",
              (char*)block - (char*)p,
              block->length);
      rc = 1;
      break;
    }

    // Validate block data.
    const size_t field_size = sizeof(block->crc32);
    char* field_start = (char*)&block->crc32;
    char* field_end = field_start + field_size;
    char field_zero[field_size];
    memset(field_zero, 0, sizeof(field_zero));
    uint32_t computed = updcrc32(-1,
                                 (char*)block,
                                 field_start - (char*)block);
    computed = updcrc32(computed, field_zero, sizeof(field_zero));
    computed = updcrc32(computed,
                        field_end,
                        (char*)block_end - field_end);
    computed = ~computed;

    if(block->crc32 != computed) {
      fprintf(stderr,
              "fatal: crc32 check failed: "
              "expected 0x%x, but was 0x%x, "
              "block offset is 0x%tx\n",
              block->crc32,
              computed,
              (char*)block - (char*)p);
      rc = 1;
      break;
    }

    struct tlv_t* previous_tlv = NULL;
    for(struct tlv_t* tlv = (tlv_t*)&block->data;
        tlv < block_end && rc == 0;
        previous_tlv = tlv,
        tlv = aligned_tlv((char*)tlv + tlv->length),
        tlv_count++) {
      switch(tlv->type) {
      case TYPE_FRAG: {
        frag_entry_t entry;
        entry.frag = (frag_t*)tlv->value;
        auto it = frags.find(entry.frag->id);
        if(it == frags.end()) {
          frags[entry.frag->id] = entry;
          if(entry.frag->id == track_frag) {
            fprintf(stderr,
                    "info: fragment " FRAG_ID_FMT " created, "
                    "TLV offset is 0x%tx\n",
                    entry.frag->id,
                    (char*)tlv - (char*)p);
            dump_code(entry.frag);
          }
        } else {
          fprintf(stderr,
                  "fatal: duplicate fragment " FRAG_ID_FMT " created, "
                  "TLV offset is 0x%tx, "
                  "original offset is 0x%tx\n",
                  entry.frag->id,
                  (char*)tlv - (char*)p,
                  (char*)it->second.frag - (char*)p);
          rc = 1;
        }
        break;
      }
      case TYPE_FRAG_DEL: {
        struct frag_del_t* frag_del = (struct frag_del_t*)tlv->value;
        auto it = frags.find(frag_del->frag_id);
        if(it == frags.end()) {
#if 0
          fprintf(stderr,
                  "warning: non-existent fragment " FRAG_ID_FMT " deleted, "
                  "TLV offset is 0x%tx\n",
                  frag_del->frag_id,
                  (char*)tlv - (char*)p);
#endif
        } else {
          if(frag_del->frag_id == track_frag) {
            fprintf(stderr,
                    "info: fragment " FRAG_ID_FMT " deleted, "
                    "TLV offset is 0x%tx\n",
                    frag_del->frag_id,
                    (char*)tlv - (char*)p);
          }
          frags.erase(it);
        }
        break;
      }
      case TYPE_TRACE: {
        struct trace_t* trace = (struct trace_t*)tlv->value;
        size_t count = trace_count(trace);
        for(size_t i = 0; i < count; i++) {
          auto it = frags.find(trace->frag_id[i]);
          if(it == frags.end()) {
#if 0
            fprintf(stderr,
                    "warning: non-existent fragment " FRAG_ID_FMT " executed, "
                    "TLV offset is 0x%tx\n",
                    trace->frag_id[i],
                    (char*)tlv - (char*)p);
#endif
          }
          frags_executed++;
        }
        break;
      }
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
        rc = 1;
        break;
      }
    }
  }
  fprintf(stderr, "info: block count = %zu\n", block_count);
  fprintf(stderr, "info: tlv count = %zu\n", tlv_count);
  fprintf(stderr, "info: frag count = %zu\n", frags.size());
  fprintf(stderr, "info: frags executed = %zu\n", frags_executed);

  return rc;
}
