#pragma once

#include <stdint.h>

/** Basic block translation information. */
#define TYPE_BB 0x42424242
struct bb_t {
  /** Address of first instruction. */
  uint64_t pc;

  /** Raw bytes. */
  uint8_t code[];
};

/** Instruction execution information. */
#define TYPE_TRACE 0x30303030
struct trace_t {
  /** Identifier of thread that performed execution. */
  uint32_t thread_id;

  /** Basic block identifiers. */
  uint32_t bb_id[];
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
