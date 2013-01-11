#include <dr_api.h>
#include <inttypes.h>
#include <hashtable.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>

#include "drtrace.h"
#include "trace_buffer.h"

//#define TRACE_DEBUG
//#define TRACE_DUMP_BB
#define TRACE_BUFFER_SIZE (16 * PAGE_SIZE)
#define MMAP_SIZE (TRACE_BUFFER_SIZE + PAGE_SIZE)
#define TRACE_FILE_NAME "./trace.out"

/** Trace file handle. */
file_t trace_file;

/** Synchronizes accesses to trace file. */
void* trace_file_lock;

/** Global trace buffer. */
struct trace_buffer_t* trace_buffer;

/** Synchronizes access to global trace buffer. */
void* trace_buffer_lock;

/** Information about instrumentation. */
struct instr_info_t {
  /** Offset of first instrumentation instruction. */
  uint32_t first_offset;

  /** Offset of fragment id store instruction. */
  uint32_t store_offset;

  /** Register in which TLS field is stored. */
  reg_id_t tls_reg;

  /** Whether value of tls_reg should be restored. */
  bool restore_tls_reg;

  /** Register in which current position in buffer is stored. */
  reg_id_t current_reg;

  /** Whether value of current_reg should be restored. */
  bool restore_current_reg;
};

/** Information associated with fragment tags. */
struct tag_info_t {
  /** Unique identifier (tags are not unique). */
  frag_id_t id;

  /** Number of deletion calls to expect. */
  uint32_t counter;

  /** Information about instrumentation code for this particular tag. */
  struct instr_info_t instr_info;
};

/** Mapping from tags to tag_info_t structures. */
hashtable_t tags;

/** Fragment identifier. */
volatile frag_id_t next_id = 1;

/** Synchronizes access to tags and next_id. */
void* tags_lock;

/** Allocates, initializes and registers a new tag_info structure.
 *  Must be called with tags_lock held. */
struct tag_info_t* tag_info_new(void* tag) {
  struct tag_info_t* tag_info = dr_global_alloc(sizeof(struct tag_info_t));
  tag_info->id = 0;
  tag_info->counter = 0;
  memset(&tag_info->instr_info, 0, sizeof(struct instr_info_t));
  hashtable_add(&tags, tag, tag_info);
  return tag_info;
}

void tag_info_reference(struct tag_info_t* tag_info) {
  tag_info->counter++;
}

frag_id_t tag_info_reset(struct tag_info_t* tag_info) {
  frag_id_t id = tag_info->id;
  tag_info->id = next_id++;
  tag_info->counter++;
  return id;
}

/** Releases existing tag_info structure. */
void tag_info_free(struct tag_info_t* tag_info) {
  dr_global_free(tag_info, sizeof(struct tag_info_t));
}

/** Releases existing tag_info structure given void*. */
void tag_info_free_raw(void* tag_info) {
  tag_info_free((struct tag_info_t*)tag_info);
}

/** ctx sanity check. */
void check_ctx(void* ctx, const char* s) {
  if(ctx == NULL) {
    dr_fprintf(STDERR, "fatal: current ctx is NULL in %s\n", s);
    dr_exit_process(1);
  }
}

/** Records fragment deletion event into trace buffer. */
void record_deletion(struct trace_buffer_t* tb, frag_id_t id) {
  struct frag_del_t* frag_del;
  bool flushed;

  tb_tlv_complete(tb);
  for(flushed = false; ; tb_flush(tb), flushed = true) {
    tb_tlv(tb, TYPE_FRAG_DEL);
    if(tb_available(tb) < sizeof(struct frag_del_t)) {
      if(flushed) {
        dr_fprintf(STDERR, "fatal: not enough buffer space after flush\n");
        dr_exit_process(1);
      }
      tb_tlv_cancel(tb);
      continue;
    } else {
      frag_del = tb->current;
      frag_del->frag_id = id;
      tb->current = frag_del + 1;
      tb_tlv_complete(tb);
      tb_tlv(tb, TYPE_TRACE);
      break;
    }
  }
}

/** Contiguous code chunk information. */
struct chunk_info_t {
  /** Application address. */
  app_pc pc;

  /** Size. */
  size_t size;
};

/** Returns code chunk of length up to _max_, corresponding to longest prefix of
 *  instruction sequence. Changes _instr_ to instruction immediately following
 *  prefix. */
struct chunk_info_t get_chunk_info(void* ctx, instr_t** instr, size_t max) {
  struct chunk_info_t chunk_info = { 0, 0 };

  for(; *instr; *instr = instr_get_next(*instr)) {
    app_pc pc;
    size_t size;

    pc = dr_app_pc_for_decoding(instr_get_app_pc(*instr));
    if(pc != chunk_info.pc + chunk_info.size) {
      if(chunk_info.pc == 0 && chunk_info.size == 0) {
        chunk_info.pc = pc;
      } else {
        break;
      }
    }
    size = chunk_info.size + instr_length(ctx, *instr);
    if(size > max) {
      break;
    }
    chunk_info.size = size;
  }
  return chunk_info;
}

/** Records code chunk, corresponding to longest prefix of instruction sequence,
 *  into buffer [current, end). Changes _instr_ to instruction immediately
 *  following prefix. Returns next position in the buffer, or NULL if there is
 *  not enough space. */
void* record_chunk(void* ctx, instr_t** instr, void* current, void* end) {
  struct code_chunk_t* chunk;
  ssize_t max;
  struct chunk_info_t chunk_info;

  chunk = current;
  max = end - current - sizeof(struct code_chunk_t);
  if(max <= 0) {
    return NULL;
  }
  if(max > UINT8_MAX) {
    max = UINT8_MAX;
  }
  chunk_info = get_chunk_info(ctx, instr, max);
  if(chunk_info.size == 0) {
    return NULL;
  }
  chunk->pc = (uintptr_t)chunk_info.pc;
  chunk->size = (uint8_t)chunk_info.size;
  memcpy(chunk->code, chunk_info.pc, chunk_info.size);
  return &chunk->code[chunk_info.size];
}

/** Records code chunks corresponding to given fragment into buffer
 *  [current, end). Returns next position in the buffer, or NULL if there is
 *  not enough space. */
void* record_frag_instrs(void* ctx,
                         instrlist_t* frag,
                         void* current,
                         void* end) {
  instr_t* instr;

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR, "debug: record_frag_instrs(%p-%p)\n", current, end);
#endif

  instr = instrlist_first(frag);
  while(instr) {
    current = record_chunk(ctx, &instr, current, end);
    if(!current) {
      break;
    }
  }
  return current;
}

/** Records given fragment. */
void record_frag(void* ctx, instrlist_t* frag, frag_id_t id) {
  bool flushed;
  struct trace_buffer_t* tb;

  tb = dr_get_tls_field(ctx);
  tb_tlv_complete(tb);
  for(flushed = false; ; tb_flush(tb), flushed = true) {
    struct frag_t* frag_data;
    void* current;

    tb_tlv(tb, TYPE_FRAG);
    frag_data = tb->current;
    current = record_frag_instrs(ctx, frag, &frag_data->chunks, tb_end(tb));
    if(current) {
      frag_data->id = id;
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

/** Returns offset, in bytes, between starts of the first and the second
 *  instruction. Returns -1 if the second instruction does not follow the first
 *  instruction. */
int get_offset(void* ctx, instr_t* first, instr_t* second) {
  int offset = 0;
  while(first != second) {
    if(first == NULL) {
      return -1;
    }
    offset += instr_length(ctx, first);
    first = instr_get_next(first);
  }
  return offset;
}

/** Combines instr_set_translation and instrlist_meta_preinsert calls. */
instr_t* prexl8(instrlist_t* frag, instr_t* where, instr_t* instr, app_pc pc) {
  instr_set_translation(instr, pc);
  instrlist_meta_preinsert(frag, where, instr);
  return instr;
}

/** Selects registers that should be used for instrumenting given fragment.
 *  Returns a place where instrumentation should be inserted. */
instr_t* configure_instr(struct instr_info_t* instr_info, instrlist_t* frag) {
  // TODO: find dead registers
  instr_info->tls_reg = DR_REG_XAX;
  instr_info->restore_tls_reg = true;
  instr_info->current_reg = DR_REG_XDX;
  instr_info->restore_current_reg = true;
  return instrlist_first(frag);
}

/** Adds instrumentation that records fragment execution. */
struct instr_info_t instrument_frag(void* ctx,
                                    instrlist_t* frag,
                                    frag_id_t id) {
  const size_t offsetof_current = offsetof(struct trace_buffer_t, current);
  ptr_int_t frag_id = id; // sign-extended for OPND_CREATE_INT32
  app_pc xl8_pc;
  instr_t* where;
  app_pc pc;
  instr_t* before;
  struct instr_info_t instr_info;
  instr_t* store;
  instr_t* first;

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR, "debug: instrument_frag(0x%" PRIxPTR ")\n", frag_id);
#endif

  xl8_pc = instr_get_app_pc(instrlist_first(frag));

#ifdef TRACE_DUMP_BB
  instrlist_disassemble(ctx, xl8_pc, frag, STDERR);
#endif

  where = configure_instr(&instr_info, frag);
  pc = instr_get_app_pc(where);
  before = instr_get_prev(where);

#define INSERT(instr) prexl8(frag, where, (instr), xl8_pc)

  // Add instrumentation.
  // save tls_reg
  if(instr_info.restore_tls_reg) {
    dr_save_reg(ctx, frag, where, instr_info.tls_reg, SPILL_SLOT_2);
  }
  // save current_reg
  if(instr_info.restore_current_reg) {
    dr_save_reg(ctx, frag, where, instr_info.current_reg, SPILL_SLOT_3);
  }
  // tls_reg = tb
  dr_insert_read_tls_field(ctx, frag, where, instr_info.tls_reg);
  // current_reg = tb->current
  INSERT(
      INSTR_CREATE_mov_ld(
          ctx,
          opnd_create_reg(instr_info.current_reg),
          OPND_CREATE_MEMPTR(instr_info.tls_reg, offsetof_current)));
  // *current_reg = bb_id
  store = INSERT(
      INSTR_CREATE_mov_st(
          ctx,
          OPND_CREATE_MEMPTR(instr_info.current_reg, 0),
          OPND_CREATE_INT32(frag_id)));
  // current_reg += sizeof(bb_id)
  INSERT(
      INSTR_CREATE_lea(
          ctx,
          opnd_create_reg(instr_info.current_reg),
          OPND_CREATE_MEM_lea(instr_info.current_reg,
                              DR_REG_NULL,
                              0,
                              sizeof(frag_id_t))));
  // tb->current = current_reg
  INSERT(
      INSTR_CREATE_mov_st(
          ctx,
          OPND_CREATE_MEMPTR(instr_info.tls_reg, offsetof_current),
          opnd_create_reg(instr_info.current_reg)));
  // restore current_reg
  if(instr_info.restore_current_reg) {
    dr_restore_reg(ctx, frag, where, instr_info.current_reg, SPILL_SLOT_3);
  }
  // restore tls_reg
  if(instr_info.restore_tls_reg) {
    dr_restore_reg(ctx, frag, where, instr_info.tls_reg, SPILL_SLOT_2);
  }

#undef INSERT

  // Compute instrumentation instructions offsets.
  if(before) {
    first = instr_get_next(before);
  } else {
    first = instrlist_first(frag);
  }
  instr_info.first_offset = get_offset(ctx,
                                       instrlist_first(frag),
                                       first);
  instr_info.store_offset = get_offset(ctx,
                                       instrlist_first(frag),
                                       store);

#ifdef TRACE_DUMP_BB
  instrlist_disassemble(ctx, xl8_pc, frag, STDERR);
#endif
#ifdef TRACE_DEBUG
  dr_fprintf(STDERR,
             "debug: instrument_frag() done,"
             " first_offset=0x%" PRIx32
             " store_offset=0x%" PRIx32
             "\n",
             instr_info.first_offset,
             instr_info.store_offset);
#endif

  return instr_info;
}

/** Finds information associated with given tag. */
struct tag_info_t* find_tag_or_die(void* tag) {
  struct tag_info_t* tag_info;

  dr_mutex_lock(tags_lock);
  tag_info = hashtable_lookup(&tags, tag);
  dr_mutex_unlock(tags_lock);
  if(tag_info == NULL) {
    dr_fprintf(STDERR, "fatal: could not locate tag %p\n", tag);
    dr_exit_process(1);
  }
  return tag_info;
}

/** Checks whether raw_mcontext corresponds to failed guard page access by
 *  instrumentation. */
bool is_guard_page_access(dr_mcontext_t* raw_mcontext,
                          struct tag_info_t* tag_info,
                          app_pc cache_start_pc) {
  uint32_t offset;

  offset = raw_mcontext->xip - cache_start_pc;
#ifdef TRACE_DEBUG
  dr_fprintf(STDERR,
             "debug: xip = %p, "
             "cache = %p, "
             "offset = 0x%" PRIx32 ", "
             "store offset = 0x%" PRIx32 "\n",
             raw_mcontext->xip,
             cache_start_pc,
             offset,
             tag_info->instr_info.store_offset);
#endif
  return offset == tag_info->instr_info.store_offset;
}

/** Restores state after guard page hit. */
void restore_state(void* ctx,
                   dr_mcontext_t* mcontext,
                   struct tag_info_t* tag_info) {
  struct instr_info_t* instr_info;

  instr_info = &tag_info->instr_info;
  if(instr_info->restore_tls_reg) {
    reg_set_value(instr_info->tls_reg,
                  mcontext,
                  dr_read_saved_reg(ctx, SPILL_SLOT_2));
  }
  if(instr_info->restore_current_reg) {
    reg_set_value(instr_info->current_reg,
                  mcontext,
                  dr_read_saved_reg(ctx, SPILL_SLOT_3));
  }
}

// XXX: use exceptions on Windows
dr_signal_action_t handle_signal(void* ctx, dr_siginfo_t* siginfo) {
  dr_fprintf(STDERR, "info: caught signal %u\n", (unsigned int)siginfo->sig);
  if(siginfo->sig == SIGSEGV) {
    struct trace_buffer_t* tb;
    struct tag_info_t* tag_info;

    if(siginfo->raw_mcontext == NULL) {
      dr_fprintf(STDERR, "fatal: raw_mcontext missing\n");
      dr_exit_process(1);
    }
#ifdef TRACE_DEBUG
    dr_fprintf(STDERR, "debug: offending instruction is\n");
    disassemble(ctx, siginfo->raw_mcontext->xip, STDERR);
#endif

    tag_info = find_tag_or_die(siginfo->fault_fragment_info.tag);
    if(is_guard_page_access(siginfo->raw_mcontext,
                            tag_info,
                            siginfo->fault_fragment_info.cache_start_pc)) {
#ifdef TRACE_DEBUG
      dr_fprintf(STDERR, "debug: this is guard page access\n");
#endif

      // Flush.
      tb = dr_get_tls_field(siginfo->drcontext);
      tb_flush(tb);
      tb_tlv(tb, TYPE_TRACE);

      // Restart instrumentation.
      siginfo->raw_mcontext->xip = siginfo->fault_fragment_info.cache_start_pc +
                                   tag_info->instr_info.first_offset;
      restore_state(ctx, siginfo->raw_mcontext, tag_info);
      return DR_SIGNAL_SUPPRESS;
    }
  }
  return DR_SIGNAL_DELIVER;
}

void handle_restore_state(void* ctx,
                          void* tag,
                          dr_mcontext_t* mcontext,
                          bool restore_memory,
                          bool app_code_consistent) {
#ifdef TRACE_DEBUG
  dr_fprintf(STDERR, "debug: restoring state for tag=%p..\n", tag);
#endif

  restore_state(ctx, mcontext, find_tag_or_die(tag));
}

/** Common handler for basic blocks and traces. */
void handle_frag(void* ctx,
                 void* tag,
                 instrlist_t* frag,
                 bool new_frag,
                 bool instrument,
                 frag_id_t id_mask) {
  struct trace_buffer_t* tb;
  frag_id_t deleted_id;
  struct tag_info_t* tag_info;

  tb = dr_get_tls_field(ctx);

  deleted_id = 0;
  dr_mutex_lock(tags_lock);
  tag_info = hashtable_lookup(&tags, tag);
  if(tag_info == NULL) {
    tag_info = tag_info_new(tag);
  }
  if(new_frag) {
    deleted_id = tag_info_reset(tag_info);
    tag_info->id |= id_mask;
  } else {
    tag_info_reference(tag_info);
  }
  dr_mutex_unlock(tags_lock);

  if(deleted_id) {
    record_deletion(tb, deleted_id);
  }

  if(new_frag) {
    record_frag(ctx, frag, tag_info->id);
  }

  if(instrument) {
    struct instr_info_t instr_info;

    instr_info = instrument_frag(ctx, frag, tag_info->id);
    if(new_frag) {
      tag_info->instr_info = instr_info;
    }
  }
}

dr_emit_flags_t handle_bb(void* ctx,
                          void* tag,
                          instrlist_t* bb,
                          bool for_trace,
                          bool translating) {
  bool new_frag;
  bool instrument;

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR,
             "debug: handle_bb(tag=%p, for_trace=%u, translating=%u)\n",
             tag,
             for_trace,
             translating);
#endif

  check_ctx(ctx, "handle_bb");

  new_frag = true;
  instrument = true;
  if(for_trace) {
    // Traces are instrumented separately, we only need to increment counter.
    new_frag = false;
    instrument = false;
  }
  if(translating) {
    // Reuse existing fragment when translating.
    new_frag = false;
  }

  handle_frag(ctx, tag, bb, new_frag, instrument, 0);

  return DR_EMIT_DEFAULT;
}

dr_emit_flags_t handle_trace(void* ctx,
                             void* tag,
                             instrlist_t* trace,
                             bool translating) {
#ifdef TRACE_DEBUG
  dr_fprintf(STDERR,
             "debug: handle_trace(tag=%p, translating=%u)\n",
             tag,
             translating);
#endif

  check_ctx(ctx, "handle_trace");

  handle_frag(ctx, tag, trace, !translating, true, FRAG_ID_MSB);

  return DR_EMIT_DEFAULT;
}

void handle_delete(void* ctx, void* tag) {
  struct tag_info_t* tag_info;
  frag_id_t id;
  struct trace_buffer_t* tb;

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR, "debug: handle_delete(tag=%p)\n", tag);
#endif

  dr_mutex_lock(tags_lock);
  tag_info = hashtable_lookup(&tags, tag);
  if(tag_info == NULL) {
    // Ignore -- this must be trace tag.
    dr_mutex_unlock(tags_lock);
    return;
  }
  if(--tag_info->counter != 0) {
    // Ignore -- this deletion was already reported.
    dr_mutex_unlock(tags_lock);
    return;
  }
  id = tag_info->id;
  hashtable_remove(&tags, tag);
  dr_mutex_unlock(tags_lock);

  if(ctx == NULL) {
    dr_mutex_lock(trace_buffer_lock);
    tb = trace_buffer;
  } else {
    tb = dr_get_tls_field(ctx);
  }
  record_deletion(tb, id);
  if(tb == trace_buffer) {
    dr_mutex_unlock(trace_buffer_lock);
  }
}

struct trace_buffer_t* tb_create(thread_id_t thread_id) {
  size_t size;
  struct trace_buffer_t* tb;

  size = MMAP_SIZE;
  // XXX: will -1 work on Windows?
  tb = dr_map_file(-1, &size, 0, 0, DR_MEMPROT_READ | DR_MEMPROT_WRITE, 0);
  if(!tb) {
    dr_fprintf(STDERR, "fatal: dr_map_file() failed\n");
    dr_exit_process(1);
  }
  if((uintptr_t)tb % PAGE_SIZE != 0 || size != MMAP_SIZE) {
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

void tb_delete(struct trace_buffer_t* tb) {
  tb_flush(tb);
  if(!dr_unmap_file(tb, TRACE_BUFFER_SIZE)) {
      dr_fprintf(STDERR, "warning: dr_unmap_file() failed\n");
  }
}

void handle_thread_init(void* ctx) {
  thread_id_t thread_id;
  struct trace_buffer_t* tb;

  check_ctx(ctx, "handle_thread_init");
  thread_id = dr_get_thread_id(ctx);
  dr_fprintf(STDERR,
             "info: initializing thread 0x%" PRIx64 "..\n",
             (uint64_t)thread_id);
  tb = tb_create(thread_id);
  dr_set_tls_field(ctx, tb);
  tb_tlv(tb, TYPE_TRACE);
}

void handle_thread_exit(void* ctx) {
  thread_id_t thread_id;
  struct trace_buffer_t* tb;

  check_ctx(ctx, "handle_thread_exit");
  thread_id = dr_get_thread_id(ctx);
  dr_fprintf(STDERR,
             "info: cleaning up thread 0x%" PRIx64 "..\n",
             (uint64_t)thread_id);
  tb = dr_get_tls_field(ctx);
  tb_delete(tb);
  dr_set_tls_field(ctx, NULL);
}

void dr_exit() {
  dr_fprintf(STDERR, "info: stopping dtrace..\n");

  tb_delete(trace_buffer);
  dr_mutex_destroy(trace_buffer_lock);

  dr_close_file(trace_file);
  dr_mutex_destroy(trace_file_lock);

  hashtable_delete(&tags);
  dr_mutex_destroy(tags_lock);

  dr_unregister_exit_event(&dr_exit);
  dr_unregister_thread_init_event(&handle_thread_init);
  dr_unregister_thread_exit_event(&handle_thread_exit);
  dr_unregister_bb_event(&handle_bb);
  dr_unregister_trace_event(&handle_trace);
  dr_unregister_delete_event(&handle_delete);
  dr_unregister_signal_event(&handle_signal);
  dr_unregister_restore_state_event(&handle_restore_state);
}

DR_EXPORT void dr_init(client_id_t id) {
  dr_fprintf(STDERR, "info: starting dtrace, &dr_init=%p..\n", &dr_init);

  trace_file = dr_open_file(TRACE_FILE_NAME,
                            DR_FILE_ALLOW_LARGE | DR_FILE_WRITE_OVERWRITE);
  if(trace_file == INVALID_FILE) {
    dr_fprintf(STDERR, "fatal: dr_open_file() failed\n");
    dr_exit_process(1);
  }
  trace_file_lock = dr_mutex_create();

  trace_buffer = tb_create(-1);
  trace_buffer_lock = dr_mutex_create();

  hashtable_init_ex(&tags,
                    16,
                    HASH_INTPTR,
                    false,
                    false,
                    &tag_info_free_raw,
                    NULL,
                    NULL);
  tags_lock = dr_mutex_create();

  dr_register_exit_event(&dr_exit);
  dr_register_thread_init_event(&handle_thread_init);
  dr_register_thread_exit_event(&handle_thread_exit);
  dr_register_bb_event(&handle_bb);
  dr_register_trace_event(&handle_trace);
  dr_register_delete_event(&handle_delete);
  dr_register_signal_event(&handle_signal);
  dr_register_restore_state_event(&handle_restore_state);
}
