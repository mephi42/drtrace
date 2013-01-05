#pragma once

#include <dr_api.h>

#include "drtrace.h"

/** Header of per-thread buffer. Immediately followed by raw data. */
struct thread_buffer_t {
  /** Size including this header. */
  size_t size;

  /** Backing file. */
  file_t file;

  /** Backing file lock. */
  void* mutex;

  /** Associated thread identifier. */
  thread_id_t thread_id;

  /** TLV currently being written. */
  struct tlv_t* current_tlv;

  /** Current position in raw TLV data. */
  void* current;
};

/** Number of available bytes. */
size_t tb_available(struct thread_buffer_t* tb);

/** Address of byte after last. */
void* tb_end(struct thread_buffer_t* tb);

/** Moves data from trace buffer to trace file. */
void tb_flush(struct thread_buffer_t* tb);

/** Initializes trace buffer. */
void tb_init(struct thread_buffer_t* tb,
             size_t size,
             file_t file,
             void* mutex,
             thread_id_t thread_id);

/** Begins a new TLV. */
void tb_tlv(struct thread_buffer_t* tb, uint32_t type);

/** Cancels current TLV. */
void tb_tlv_cancel(struct thread_buffer_t* tb);

/** Checks if current TLV has given type. */
bool tb_tlv_is(struct thread_buffer_t* tb, uint32_t type);

/** Completes current TLV. */
void tb_tlv_complete(struct thread_buffer_t* tb);
