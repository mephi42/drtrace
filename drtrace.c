#include <dr_api.h>
#include <dr_events.h>
#include <dr_ir_utils.h>
#include <dr_tools.h>
#include <hashtable.h>
#include <string.h>

#include "drtrace.h"
#include "trace_buffer.h"

//#define TRACE_DEBUG
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

/** Information associated with fragment tags. */
struct tag_info_t {
  /** Unique identifier (tags are not unique). */
  frag_id_t id;

  /** Number of deletion calls to expect. */
  uint32_t counter;
};

/** Mapping from tags to tag_info_t structures. */
hashtable_t tags;

/** Fragment identifier. */
frag_id_t next_id = 1;

/** Synchronizes access to tags and next_id. */
void* tags_lock;

/** Allocates a new tag_info structure. */
struct tag_info_t* tag_info_alloc() {
  return dr_global_alloc(sizeof(struct tag_info_t));
}

/** Releases existing tag_info structure. */
void tag_info_free(struct tag_info_t* tag_info) {
  dr_global_free(tag_info, sizeof(struct tag_info_t));
}

/** Releases existing tag_info structure given void*. */
void tag_info_free_raw(void* tag_info) {
  tag_info_free((struct tag_info_t*)tag_info);
}

/** drcontext sanity check. */
void check_drcontext(void* drcontext, const char* s) {
  if(drcontext == NULL) {
    dr_fprintf(STDERR, "fatal: current drcontext is NULL in %s\n", s);
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

/** Records fragment execution event into trace buffer of current thread. */
void handle_frag_exec(frag_id_t id) {
  void* drcontext;
  struct trace_buffer_t* tb;

  drcontext = dr_get_current_drcontext();
  check_drcontext(drcontext, "handle_bb_exec");
  tb = dr_get_tls_field(drcontext);
  if(tb_available(tb) < sizeof(void*)) {
    tb_flush(tb);
    tb_tlv(tb, TYPE_TRACE);
  }
  *(frag_id_t*)tb->current = id;
  tb->current += sizeof(frag_id_t);
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
struct chunk_info_t get_chunk_info(void* drcontext,
                                   instr_t** instr,
                                   size_t max) {
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
    size = chunk_info.size + instr_length(drcontext, *instr);
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
void* record_chunk(void* drcontext,
                   instr_t** instr,
                   void* current,
                   void* end) {
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
  chunk_info = get_chunk_info(drcontext, instr, max);
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
void* record_frag_instrs(void* drcontext,
                         instrlist_t* frag,
                         void* current,
                         void* end) {
  instr_t* instr;

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR, "debug: record_frag_instrs(%p-%p)\n", current, end);
#endif

  instr = instrlist_first(frag);
  while(instr) {
    current = record_chunk(drcontext, &instr, current, end);
    if(!current) {
      break;
    }
  }
  return current;
}

/** Records given fragment. */
void record_frag(void* drcontext,
                 instrlist_t* frag,
                 frag_id_t id) {
  bool flushed;
  struct trace_buffer_t* tb;

  tb = dr_get_tls_field(drcontext);
  tb_tlv_complete(tb);
  for(flushed = false; ; tb_flush(tb), flushed = true) {
    struct frag_t* frag_data;
    void* current;

    tb_tlv(tb, TYPE_FRAG);
    frag_data = tb->current;
    current = record_frag_instrs(drcontext,
                                 frag,
                                 &frag_data->chunks,
                                 tb_end(tb));
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

dr_emit_flags_t handle_bb(void* drcontext,
                          void* tag,
                          instrlist_t* bb,
                          bool for_trace,
                          bool translating) {
  instr_t* first;
  struct trace_buffer_t* tb;
  bool record_creation;
  frag_id_t record_deleted_id;
  frag_id_t id;
  struct tag_info_t* tag_info;

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR,
             "debug: handle_bb(tag=%p, for_trace=%u, translating=%u)\n",
             tag,
             for_trace,
             translating);
#endif

  check_drcontext(drcontext, "handle_bb");

  first = instrlist_first(bb);
  tb = dr_get_tls_field(drcontext);

  record_deleted_id = 0;
  record_creation = !translating;
  dr_mutex_lock(tags_lock);
  tag_info = hashtable_lookup(&tags, tag);
  if(tag_info == NULL) {
    // This is the first time we see this tag.
    tag_info = tag_info_alloc();
    id = next_id++;
    tag_info->id = id;
    tag_info->counter = 1;
    hashtable_add(&tags, tag, tag_info);
  } else {
    // This tag was already seen.
    if(for_trace) {
      // Use the same identifier for trace instrumentation.
      record_creation = false;
      id = tag_info->id;
      tag_info->counter++;
    } else {
      // This is tag reuse. Generate a new identifier and delete an old one.
      record_deleted_id = tag_info->id;
      id = next_id++;
      tag_info->id = id;
      tag_info->counter++;
    }
  }
  dr_mutex_unlock(tags_lock);

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR,
             "debug: id=" FRAG_ID_FMT
             ", record_deletion=" FRAG_ID_FMT
             ", record_creation=%u\n",
             id,
             report_deletion,
             record_creation);
#endif

  if(record_deleted_id) {
    record_deletion(tb, record_deleted_id);
  }

  if(record_creation) {
    record_frag(drcontext, bb, id);
  }

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR, "debug: instrumenting..\n");
#endif
  dr_insert_clean_call(drcontext,
                       bb,
                       first,
                       &handle_frag_exec,
                       false,
                       1,
                       OPND_CREATE_INT32(id));
#ifdef TRACE_DEBUG
  dr_fprintf(STDERR, "debug: done\n");
#endif

  return DR_EMIT_DEFAULT;
}

void handle_delete(void* drcontext, void* tag) {
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

  if(drcontext == NULL) {
    dr_mutex_lock(trace_buffer_lock);
    tb = trace_buffer;
  } else {
    tb = dr_get_tls_field(drcontext);
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

void tb_delete(struct trace_buffer_t* tb) {
  tb_flush(tb);
  if(!dr_unmap_file(tb, TRACE_BUFFER_SIZE)) {
      dr_fprintf(STDERR, "warning: dr_unmap_file() failed\n");
  }
}

void handle_thread_init(void* drcontext) {
  thread_id_t thread_id;
  struct trace_buffer_t* tb;

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
  struct trace_buffer_t* tb;

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

  hashtable_delete(&tags);
  dr_mutex_destroy(tags_lock);

  dr_unregister_exit_event(&dr_exit);
  dr_unregister_thread_init_event(&handle_thread_init);
  dr_unregister_thread_exit_event(&handle_thread_exit);
  dr_unregister_bb_event(&handle_bb);
  dr_unregister_delete_event(&handle_delete);
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
  dr_register_delete_event(&handle_delete);
}
