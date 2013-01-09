#pragma once

#include <dr_api.h>

#include "drtrace.h"

/** Header of trace buffer. Immediately followed by raw data. */
struct trace_buffer_t {
  /** Size including this header. */
  size_t size;

  /** Backing file. */
  file_t file;

  /** Backing file lock. */
  void* mutex;

  /** TLV currently being written. */
  struct tlv_t* current_tlv;

  /** Current position in raw TLV data. */
  void* current;

  /** Block header. */
  struct block_t block;
};

/** Number of available bytes. */
size_t tb_available(struct trace_buffer_t* tb);

/** Address of byte after last. */
void* tb_end(struct trace_buffer_t* tb);

/** Moves data from trace buffer to trace file. */
void tb_flush(struct trace_buffer_t* tb);

/** Initializes trace buffer. */
void tb_init(struct trace_buffer_t* tb,
             size_t size,
             file_t file,
             void* mutex,
             thread_id_t thread_id);

/** Begins a new TLV. */
void tb_tlv(struct trace_buffer_t* tb, uint32_t type);

/** Cancels current TLV. */
void tb_tlv_cancel(struct trace_buffer_t* tb);

/** Checks if current TLV has given type. */
bool tb_tlv_is(struct trace_buffer_t* tb, uint32_t type);

/** Completes current TLV. */
void tb_tlv_complete(struct trace_buffer_t* tb);
