#include <dr_api.h>
#include <dr_events.h>
#include <dr_ir_utils.h>
#include <dr_tools.h>
#include <signal.h>
#include <stddef.h>

#include "drtrace.h"

#define TRACE_DEBUG
#define TRACE_DUMP_BB
#define TRACE_BUFFER_SIZE (16 * PAGE_SIZE)
#define MMAP_SIZE (TRACE_BUFFER_SIZE + PAGE_SIZE)
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

const size_t offsetof_current = offsetof(struct thread_buffer_t, current);

size_t tb_available(struct thread_buffer_t* tb);
void* tb_end(struct thread_buffer_t* tb);
void tb_flush(struct thread_buffer_t* tb);
void tb_tlv(struct thread_buffer_t* tb, uint32_t type);
void tb_tlv_cancel(struct thread_buffer_t* tb);
void tb_tlv_complete(struct thread_buffer_t* tb);

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
    if(tb->current_tlv->type == TYPE_TRACE &&
       tb->current_tlv->length == sizeof(struct tlv_t)) {
      // Do not keep empty trace TLVs.
      tb_tlv_cancel(tb);
    } else {
      tb->current_tlv = NULL;
    }
  }
}

/** Cancels current TLV. */
void tb_tlv_cancel(struct thread_buffer_t* tb) {
  tb->current = tb->current_tlv;
  tb->current_tlv = NULL;
}

/** Begins a new TLV. */
void tb_tlv(struct thread_buffer_t* tb, uint32_t type) {
  if(tb_available(tb) < sizeof(struct tlv_t)) {
    tb_flush(tb);
  }
  tb->current_tlv = tb->current;
  tb->current_tlv->type = type;
  tb->current = tb->current_tlv + 1;
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
  instr_t* first;
  app_pc pc;
  struct thread_buffer_t* tb;
  bool flushed;
  struct bb_t* bb_data;
  void* current;
  int imm;

  first = instrlist_first(bb);
  pc = instr_get_app_pc(first);
  tb = dr_get_tls_field(drcontext);

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR,
             "debug: processing bb with tag=%p, pc=%p, translating=%u..\n",
             tag,
             pc,
             (unsigned int)translating);
#endif

  // Save basic block information.
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
        bb_data->id = (uintptr_t)tag;
        bb_data->pc = (uintptr_t)pc;
        tb->current = current;
        tb_tlv_complete(tb);
        tb_tlv(tb, TYPE_TRACE);
        break;
      } else {
        if(flushed) {
          dr_fprintf(STDERR, "fatal: instrlist_encode_to_copy() failed\n");
          dr_exit_process(1);
        }
        tb_tlv_cancel(tb);
      }
    }
  }

#ifdef TRACE_DUMP_BB
  instrlist_disassemble(drcontext, pc, bb, STDERR);
#endif

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR, "debug: instrumenting..\n");
#endif

#define INSERT(instr) \
  do { \
    instr_t* _instr = (instr); \
    instr_set_translation(_instr, pc); \
    instrlist_meta_preinsert(bb, first, _instr); \
  } while(false);

  // Add instrumentation.
  // XXX: find dead registers and don't save/restore.
  reg_id_t tls_reg = DR_REG_XAX;
  reg_id_t current_reg = DR_REG_XDX;
  // save tls_reg
  dr_save_reg(drcontext, bb, first, tls_reg, SPILL_SLOT_2);
  // save current_reg
  dr_save_reg(drcontext, bb, first, current_reg, SPILL_SLOT_3);
  // tls_reg = tb
  dr_insert_read_tls_field(drcontext, bb, first, tls_reg);
  // current_reg = tb->current
  INSERT(
      INSTR_CREATE_mov_ld(drcontext,
                          opnd_create_reg(current_reg),
                          OPND_CREATE_MEMPTR(tls_reg, offsetof_current)));
  // *current_reg = bb_id
  imm = (ptr_int_t)tag;
  INSERT(
      INSTR_CREATE_mov_st(drcontext,
                          OPND_CREATE_MEMPTR(current_reg, 0),
                          opnd_create_immed_int(imm, OPSZ_4)));
#ifdef X64
  imm = (ptr_int_t)tag >> 32;
  INSERT(
      INSTR_CREATE_mov_st(drcontext,
                          OPND_CREATE_MEMPTR(current_reg, 4),
                          opnd_create_immed_int(imm, OPSZ_4)));
#endif
  // current_reg += sizeof(bb_id)
  INSERT(
      INSTR_CREATE_lea(drcontext,
                       opnd_create_reg(current_reg),
                       OPND_CREATE_MEM_lea(current_reg,
                                           DR_REG_NULL,
                                           0,
                                           opnd_size_in_bytes(OPSZ_PTR))));
  // tb->current = current_reg
  INSERT(
      INSTR_CREATE_mov_st(drcontext,
                          OPND_CREATE_MEMPTR(tls_reg, offsetof_current),
                          opnd_create_reg(current_reg)));
  // restore current_reg
  dr_restore_reg(drcontext, bb, first, current_reg, SPILL_SLOT_3);
  // restore tls_reg
  dr_restore_reg(drcontext, bb, first, tls_reg, SPILL_SLOT_2);

#ifdef TRACE_DUMP_BB
  instrlist_disassemble(drcontext, pc, bb, STDERR);
#endif

#undef INSERT

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR, "debug: done\n");
#endif

  return DR_EMIT_DEFAULT;
}

void handle_restore_state(void* drcontext,
                          void* tag,
                          dr_mcontext_t* mcontext,
                          bool restore_memory,
                          bool app_code_consistent) {
  dr_fprintf(STDERR, "info: restoring state for tag=%p..\n", tag);
}

// XXX: use exceptions on Windows
dr_signal_action_t handle_signal(void* drcontext, dr_siginfo_t* siginfo) {
  struct thread_buffer_t* tb;

  dr_fprintf(STDERR, "info: signal %u caught\n", siginfo->sig);
  if(siginfo->sig == SIGSEGV) {
    tb = dr_get_tls_field(siginfo->drcontext);
    tb_flush(tb);
    if(!siginfo->raw_mcontext_valid) {
      dr_fprintf(STDERR, "fatal: missing raw mcontext\n");
      dr_exit_process(1);
    }
#ifdef TRACE_DEBUG
    dr_fprintf(STDERR,
               "debug: raw xax=%p xbx=%p xcx=%p xdx=%p\n",
               siginfo->raw_mcontext->xax,
               siginfo->raw_mcontext->xbx,
               siginfo->raw_mcontext->xcx,
               siginfo->raw_mcontext->xdx);
    disassemble(drcontext, siginfo->raw_mcontext->xip, STDERR);
    dr_fprintf(STDERR, "debug: access=%p\n", siginfo->access_address);
#endif
    return DR_SIGNAL_DELIVER;
  }
  return DR_SIGNAL_DELIVER;
}

void handle_thread_init(void* drcontext) {
  size_t size;
  struct thread_buffer_t* tb;
  thread_id_t thread_id;

  thread_id = dr_get_thread_id(drcontext);

  dr_fprintf(STDERR,
             "info: initializing thread 0x%x..\n",
             (unsigned int)thread_id);

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
  tb->thread_id = thread_id;
  tb->current_tlv = NULL;
  tb->current = tb + 1;
  dr_set_tls_field(drcontext, tb);

  tb_tlv(tb, TYPE_TRACE);

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
  if(!dr_unmap_file(tb, MMAP_SIZE)) {
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
  dr_unregister_signal_event(&handle_signal);
  dr_unregister_restore_state_event(&handle_restore_state);
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
  dr_register_signal_event(&handle_signal);
  dr_register_restore_state_event(&handle_restore_state);
}
