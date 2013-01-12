#pragma once

#include <inttypes.h>
#include <stdint.h>

#if defined(DRTRACE_X86_32)
typedef uint32_t drtrace_uintptr_t;
#define DRTRACE_UINTPTR_FMT "0x%" PRIx32
#elif defined(DRTRACE_X86_64)
typedef uint64_t drtrace_uintptr_t;
#define DRTRACE_UINTPTR_FMT "0x%" PRIx64
#else
#error Neither DRTRACE_X86_32 nor DRTRACE_X86_64 specified
#endif

/** Aligns pointer to power-of-2 boundary. */
#define ALIGN_FORWARD(x, n) \
    ((((uintptr_t)(x)) + ((n) - 1)) & (~((uintptr_t)(n) - 1)))

/** Fragment identifier. */
typedef int32_t frag_id_t;
#define FRAG_ID_FMT "0x%x"
#define FRAG_ID_MSB 0x80000000

/** Contiguous code chunk. */
struct code_chunk_t {
  /** Address. */
  drtrace_uintptr_t pc;

  /** Size of raw code. */
  uint8_t size;

  /** Raw code. */
  uint8_t code[];
};

/** Fragment translation information. */
#define TYPE_FRAG 0x46464646
struct frag_t {
  /** Identifier. */
  frag_id_t id;

  /** Code chunks. */
  uint8_t chunks[];
};

/** Fragment deletion information. */
#define TYPE_FRAG_DEL 0x44444444
struct frag_del_t {
  /** Identifier of deleted fragment. */
  frag_id_t frag_id;
};

/** Instruction execution information. */
#define TYPE_TRACE 0x30303030
struct trace_t {
  /** Identifier of thread that performed execution. */
  uint32_t thread_id;

  /** Fragment identifiers. */
  frag_id_t frag_id[];
};

/** Block. */
struct block_t {
  /** Length. */
  uint32_t length;

  /** Checksum. */
  uint32_t crc32;

  /** Associated thread identifier. */
  uint32_t thread_id;

  /** Padding. */
  uint8_t reserved[4];

  /** Data. */
  uint8_t data[];
};

/** Type, length and value. */
struct tlv_t {
  /** Type. */
  uint32_t type;

  /** Full size, including header. */
  uint32_t length;

  /** Value. */
  uint8_t value[];
};

static __attribute__ ((unused)) struct tlv_t* aligned_tlv(void* p) {
  return (struct tlv_t*)ALIGN_FORWARD(p, sizeof(drtrace_uintptr_t));
}

static __attribute__ ((unused)) struct block_t* aligned_block(void* p) {
  return (struct block_t*)ALIGN_FORWARD(p, sizeof(drtrace_uintptr_t));
}
