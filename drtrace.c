#include <dr_api.h>
#include <dr_events.h>
#include <dr_ir_utils.h>
#include <dr_tools.h>

#include "drtrace.h"

//#define TRACE_DEBUG
#define TRACE_BUFFER_SIZE (128*1024)
#define TRACE_FILE_NAME "./trace.out"

/** Trace file handle. */
file_t trace_file;

/** Synchronizes accesses to trace file handle. */
void* trace_mutex;

/** Header of per-thread buffer. Immediately followed by raw data. */
struct thread_buffer_t {
  /** Associated thread identifier. */
  thread_id_t thread_id;

  /** TLV currently being written. */
  struct tlv_t* current_tlv;

  /** Current position in raw TLV data. */
  void* current;
};

/** Address of byte after last. */
void* tb_end(struct thread_buffer_t* tb) {
  return ((void*)tb) + TRACE_BUFFER_SIZE;
}

/** Number of available bytes. */
size_t tb_available(struct thread_buffer_t* tb) {
  return tb_end(tb) - tb->current;
}

/** Completes current TLV. */
void tb_tlv_complete(struct thread_buffer_t* tb) {
  if(tb->current_tlv) {
    tb->current_tlv->length = tb->current - (void*)tb->current_tlv;
    tb->current_tlv = NULL;
  }
}

/** Cancels current TLV. */
void tb_tlv_cancel(struct thread_buffer_t* tb) {
  tb->current = tb->current_tlv;
  tb->current_tlv = NULL;
}

/** Begins a new TLV. */
bool tb_tlv(struct thread_buffer_t* tb, uint32_t type) {
  if(tb_available(tb) < sizeof(struct tlv_t)) {
    return false;
  }
  tb->current_tlv = tb->current;
  tb->current_tlv->type = type;
  tb->current = tb->current_tlv + 1;
  return true;
}

/** Moves data from trace buffer to trace file. */
void tb_flush(struct thread_buffer_t* tb) {
  size_t size;
  size_t written;

  tb_tlv_complete(tb);

  size = tb->current - (void*)(tb + 1);
  if(size == 0) {
    // Nothing to do.
    return;
  }

  // Write data.
  dr_fprintf(STDERR,
             "info: flushing tb %p for thread 0x%x with size %u\n",
             tb,
             (unsigned int)tb->thread_id,
             (unsigned int)size);
  dr_mutex_lock(trace_mutex);
  written = dr_write_file(trace_file, tb + 1, size);
  dr_mutex_unlock(trace_mutex);
  if(written != size) {
    dr_fprintf(STDERR, "fatal: dr_write_file() failed\n");
    dr_exit_process(1);
  }

  // Reset position.
  tb->current = tb + 1;
}

dr_emit_flags_t handle_bb(void* drcontext, void* tag, instrlist_t* bb,
                          bool for_trace, bool translating) {
  struct thread_buffer_t* tb;
  app_pc pc;
  bool flushed;
  struct bb_t* bb_data;
  void* current;

  pc = instr_get_app_pc(instrlist_first(bb));

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR, "debug: processing bb %p with pc 0x%x..\n", tag, pc);
#endif

  tb = dr_get_tls_field(drcontext);
  tb_tlv_complete(tb);
  for(flushed = false; ; tb_flush(tb), flushed = true) {
    if(!tb_tlv(tb, TYPE_BB)) {
      if(flushed) {
        dr_fprintf(STDERR, "fatal: tb_tlv() failed\n");
        dr_exit_process(1);
      }
      continue;
    }
    bb_data = tb->current;
#ifdef TRACE_DEBUG
  dr_fprintf(STDERR,
             "debug: instrlist_encode_to_copy(%p-%p)..\n",
             &bb_data->code[0],
             tb_end(tb));
#endif
    current = instrlist_encode_to_copy(drcontext,
                                       bb,
                                       &bb_data->code[0],
                                       pc,
                                       tb_end(tb),
                                       true);
    if(current) {
      bb_data->pc = (uint64_t)pc;
      tb->current = current;
      tb_tlv_complete(tb);
      break;
    } else {
      if(flushed) {
        dr_fprintf(STDERR, "fatal: instrlist_encode_to_copy() failed\n");
        dr_exit_process(1);
      }
      tb_tlv_cancel(tb);
    }
  }

  return DR_EMIT_DEFAULT;
}

void handle_thread_init(void* drcontext) {
  size_t size;
  struct thread_buffer_t* tb;
  thread_id_t thread_id;

  thread_id = dr_get_thread_id(drcontext);

  dr_fprintf(STDERR,
             "info: initializing thread 0x%x..\n",
             (unsigned int)thread_id);

  size = TRACE_BUFFER_SIZE;
  // XXX: will -1 work on Windows?
  tb = dr_map_file(-1, &size, 0, 0, DR_MEMPROT_READ | DR_MEMPROT_WRITE, 0);
  if(!tb) {
    dr_fprintf(STDERR, "fatal: dr_map_file() failed\n");
    dr_exit_process(1);
  }
  if(size != TRACE_BUFFER_SIZE) {
    dr_fprintf(STDERR, "fatal: dr_map_file() returned unexpected size\n");
    dr_exit_process(1);
  }
  tb->thread_id = thread_id;
  tb->current_tlv = NULL;
  tb->current = tb + 1;
  dr_set_tls_field(drcontext, tb);

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR, "debug: tb=%p\n", tb);
#endif
}

void handle_thread_exit(void* drcontext) {
  struct thread_buffer_t* tb;

  tb = dr_get_tls_field(drcontext);

  dr_fprintf(STDERR,
             "info: cleaning up thread 0x%x..\n",
             (unsigned int)tb->thread_id);

  tb_flush(tb);
  if(!dr_unmap_file(tb, TRACE_BUFFER_SIZE)) {
      dr_fprintf(STDERR, "warning: dr_unmap_file() failed\n");
  }
}

void dr_exit() {
  dr_close_file(trace_file);

  dr_mutex_destroy(trace_mutex);

  dr_unregister_exit_event(&dr_exit);
  dr_unregister_thread_init_event(&handle_thread_init);
  dr_unregister_thread_exit_event(&handle_thread_exit);
  dr_unregister_bb_event(&handle_bb);
}

DR_EXPORT void dr_init(client_id_t id) {
  trace_file = dr_open_file(TRACE_FILE_NAME, DR_FILE_WRITE_OVERWRITE);
  if(trace_file == INVALID_FILE) {
    dr_fprintf(STDERR, "fatal: dr_open_file() failed\n");
    dr_exit_process(1);
  }

  trace_mutex = dr_mutex_create();

  dr_register_exit_event(&dr_exit);
  dr_register_thread_init_event(&handle_thread_init);
  dr_register_thread_exit_event(&handle_thread_exit);
	dr_register_bb_event(&handle_bb);
}
