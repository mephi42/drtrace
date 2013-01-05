#include <dr_api.h>
#include <dr_events.h>
#include <dr_ir_utils.h>
#include <dr_tools.h>

#include "drtrace.h"
#include "thread_buffer.h"

//#define TRACE_DEBUG
#define TRACE_BUFFER_SIZE (16 * PAGE_SIZE)
#define MMAP_SIZE (TRACE_BUFFER_SIZE + PAGE_SIZE)
#define TRACE_FILE_NAME "./trace.out"

/** Trace file handle. */
file_t trace_file;

/** Synchronizes accesses to trace file. */
void* trace_file_lock;

/** Global trace buffer. */
struct thread_buffer_t* trace_buffer;

/** Synchronizes access to global trace buffer. */
void* trace_buffer_lock;

void check_drcontext(void* drcontext, const char* s) {
  if(drcontext == NULL) {
    dr_fprintf(STDERR, "fatal: current drcontext is NULL in %s\n", s);
    dr_exit_process(1);
  }
}

void handle_bb_exec(void* tag) {
  void* drcontext;
  struct thread_buffer_t* tb;

  drcontext = dr_get_current_drcontext();
  check_drcontext(drcontext, "handle_bb_exec");
  tb = dr_get_tls_field(drcontext);
  if(tb_available(tb) < sizeof(void*)) {
    tb_flush(tb);
    tb_tlv(tb, TYPE_TRACE);
  }
  *(void**)tb->current = tag;
  tb->current += sizeof(void*);
}

dr_emit_flags_t handle_bb(void* drcontext, void* tag, instrlist_t* bb,
                          bool for_trace, bool translating) {
  instr_t* first;
  struct thread_buffer_t* tb;
  app_pc pc;
  bool flushed;
  struct bb_t* bb_data;
  void* current;

  check_drcontext(drcontext, "handle_bb");

  first = instrlist_first(bb);
  pc = instr_get_app_pc(first);
  tb = dr_get_tls_field(drcontext);

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR, "debug: bb=%p pc=%p tb=%p..\n", tag, pc, tb);
#endif

  if(!translating) {
    tb_tlv_complete(tb);
    for(flushed = false; ; tb_flush(tb), flushed = true) {
      tb_tlv(tb, TYPE_BB);
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
        bb_data->id = (uint64_t)tag;
        bb_data->pc = (uint64_t)pc;
        tb->current = current;
        tb_tlv_complete(tb);
        tb_tlv(tb, TYPE_TRACE);
        break;
      } else {
        if(flushed) {
          dr_fprintf(STDERR, "fatal: not enough buffer space after flush\n");
          dr_exit_process(1);
        }
        tb_tlv_cancel(tb);
      }
    }
  }

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR, "debug: instrumenting..\n");
#endif
  dr_insert_clean_call(drcontext,
                       bb,
                       first,
                       &handle_bb_exec,
                       false,
                       1,
                       OPND_CREATE_INTPTR(tag));
#ifdef TRACE_DEBUG
  dr_fprintf(STDERR, "debug: done\n");
#endif

  return DR_EMIT_DEFAULT;
}

void handle_delete(void* drcontext, void* tag) {
  struct thread_buffer_t* tb;
  struct bb_del_t* bb_del;
  bool flushed;

  if(drcontext == NULL) {
    dr_mutex_lock(trace_buffer_lock);
    tb = trace_buffer;
  } else {
    tb = dr_get_tls_field(drcontext);
  }
  tb_tlv_complete(tb);
  for(flushed = false; ; tb_flush(tb), flushed = true) {
    tb_tlv(tb, TYPE_BB_DEL);
    if(tb_available(tb) < sizeof(struct bb_del_t)) {
      if(flushed) {
        dr_fprintf(STDERR, "fatal: not enough buffer space after flush\n");
        dr_exit_process(1);
      }
      tb_tlv_cancel(tb);
      continue;
    } else {
      bb_del = tb->current;
      bb_del->bb_id = (uintptr_t)tag;
      tb->current = bb_del + 1;
      tb_tlv_complete(tb);
      tb_tlv(tb, TYPE_TRACE);
      break;
    }
  }
  if(tb == trace_buffer) {
    dr_mutex_unlock(trace_buffer_lock);
  }
}

struct thread_buffer_t* tb_create(thread_id_t thread_id) {
  size_t size;
  struct thread_buffer_t* tb;

  size = MMAP_SIZE;
  // XXX: will -1 work on Windows?
  tb = dr_map_file(-1, &size, 0, 0, DR_MEMPROT_READ | DR_MEMPROT_WRITE, 0);
  if(!tb) {
    dr_fprintf(STDERR, "fatal: dr_map_file() failed\n");
    dr_exit_process(1);
  }
  if((uint64_t)tb % PAGE_SIZE != 0 || size != MMAP_SIZE) {
    dr_fprintf(STDERR, "fatal: dr_map_file() returned unusable area\n");
    dr_exit_process(1);
  }
  if(!dr_memory_protect((void*)tb + MMAP_SIZE - PAGE_SIZE,
                        PAGE_SIZE,
                        DR_MEMPROT_NONE)) {
    dr_fprintf(STDERR, "fatal: dr_memory_protect() failed\n");
    dr_exit_process(1);
  }
  tb_init(tb, TRACE_BUFFER_SIZE, trace_file, trace_file_lock, thread_id);

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR, "debug: created tb=%p\n", tb);
#endif

  return tb;
}

void tb_delete(struct thread_buffer_t* tb) {
  tb_flush(tb);
  if(!dr_unmap_file(tb, TRACE_BUFFER_SIZE)) {
      dr_fprintf(STDERR, "warning: dr_unmap_file() failed\n");
  }
}

void handle_thread_init(void* drcontext) {
  thread_id_t thread_id;
  struct thread_buffer_t* tb;

  check_drcontext(drcontext, "handle_thread_init");
  thread_id = dr_get_thread_id(drcontext);
  dr_fprintf(STDERR,
             "info: initializing thread 0x%x..\n",
             (unsigned int)thread_id);
  tb = tb_create(thread_id);
  dr_set_tls_field(drcontext, tb);
  tb_tlv(tb, TYPE_TRACE);
}

void handle_thread_exit(void* drcontext) {
  struct thread_buffer_t* tb;

  check_drcontext(drcontext, "handle_thread_exit");
  tb = dr_get_tls_field(drcontext);

  dr_fprintf(STDERR,
             "info: cleaning up thread 0x%x..\n",
             (unsigned int)tb->thread_id);

  tb_delete(tb);
  dr_set_tls_field(drcontext, NULL);
}

void dr_exit() {
  dr_fprintf(STDERR, "info: stopping dtrace..\n");

  tb_delete(trace_buffer);
  dr_mutex_destroy(trace_buffer_lock);

  dr_close_file(trace_file);
  dr_mutex_destroy(trace_file_lock);

  dr_unregister_exit_event(&dr_exit);
  dr_unregister_thread_init_event(&handle_thread_init);
  dr_unregister_thread_exit_event(&handle_thread_exit);
  dr_unregister_bb_event(&handle_bb);
  dr_unregister_delete_event(&handle_delete);
}

DR_EXPORT void dr_init(client_id_t id) {
  dr_fprintf(STDERR, "info: starting dtrace..\n");

  trace_file = dr_open_file(TRACE_FILE_NAME,
                            DR_FILE_ALLOW_LARGE | DR_FILE_WRITE_OVERWRITE);
  if(trace_file == INVALID_FILE) {
    dr_fprintf(STDERR, "fatal: dr_open_file() failed\n");
    dr_exit_process(1);
  }
  trace_file_lock = dr_mutex_create();

  trace_buffer = tb_create(-1);
  trace_buffer_lock = dr_mutex_create();

  dr_register_exit_event(&dr_exit);
  dr_register_thread_init_event(&handle_thread_init);
  dr_register_thread_exit_event(&handle_thread_exit);
  dr_register_bb_event(&handle_bb);
  dr_register_delete_event(&handle_delete);
}
