#include <dr_api.h>
#include <dr_events.h>
#include <dr_ir_utils.h>
#include <dr_tools.h>
#include <hashtable.h>

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
  bb_id_t id;

  /** Number of deletion calls to expect. */
  uint32_t counter;
};

/** Mapping from tags to tag_info_t structures. */
hashtable_t tags;

/** Basic block identifier. */
bb_id_t next_id = 0;

/** Synchronizes access to tags and next_id. */
void* tags_lock;

struct tag_info_t* tag_info_alloc() {
  return dr_global_alloc(sizeof(struct tag_info_t));
}

void tag_info_free(struct tag_info_t* tag_info) {
  dr_global_free(tag_info, sizeof(struct tag_info_t));
}

void tag_info_free_raw(void* tag_info) {
  tag_info_free((struct tag_info_t*)tag_info);
}

void check_drcontext(void* drcontext, const char* s) {
  if(drcontext == NULL) {
    dr_fprintf(STDERR, "fatal: current drcontext is NULL in %s\n", s);
    dr_exit_process(1);
  }
}

void save_deletion_event(struct trace_buffer_t* tb, bb_id_t id) {
  struct bb_del_t* bb_del;
  bool flushed;

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
      bb_del->bb_id = id;
      tb->current = bb_del + 1;
      tb_tlv_complete(tb);
      tb_tlv(tb, TYPE_TRACE);
      break;
    }
  }
}

void handle_bb_exec(bb_id_t id) {
  void* drcontext;
  struct trace_buffer_t* tb;

  drcontext = dr_get_current_drcontext();
  check_drcontext(drcontext, "handle_bb_exec");
  tb = dr_get_tls_field(drcontext);
  if(tb_available(tb) < sizeof(void*)) {
    tb_flush(tb);
    tb_tlv(tb, TYPE_TRACE);
  }
  *(bb_id_t*)tb->current = id;
  tb->current += sizeof(bb_id_t);
}

void record_bb(void* drcontext,
               instrlist_t* bb,
               bb_id_t id) {
  struct trace_buffer_t* tb;
  app_pc pc;
  bool flushed;
  struct bb_t* bb_data;
  void* current;

  tb = dr_get_tls_field(drcontext);
  pc = instr_get_app_pc(instrlist_first(bb));

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
    // XXX: copy right from application memory
    current = instrlist_encode_to_copy(drcontext,
                                       bb,
                                       &bb_data->code[0],
                                       pc,
                                       tb_end(tb),
                                       true);
    if(current) {
      bb_data->id = id;
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

dr_emit_flags_t handle_bb(void* drcontext, void* tag, instrlist_t* bb,
                          bool for_trace, bool translating) {
  instr_t* first;
  struct trace_buffer_t* tb;
  bool report_creation;
  bb_id_t report_deletion;
  bb_id_t id;
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

  report_deletion = 0;
  report_creation = !translating;
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
      report_creation = false;
      id = tag_info->id;
      tag_info->counter++;
    } else {
      // This is tag reuse. Generate a new identifier and delete an old one.
      report_deletion = tag_info->id;
      id = next_id++;
      tag_info->id = id;
      tag_info->counter++;
    }
  }
  dr_mutex_unlock(tags_lock);

#ifdef TRACE_DEBUG
  dr_fprintf(STDERR,
             "debug: id=" BB_ID_FMT
             ", report_deletion=" BB_ID_FMT
             ", report_creation=%u\n",
             id,
             report_deletion,
             report_creation);
#endif

  if(report_deletion) {
    save_deletion_event(tb, report_deletion);
  }

  if(report_creation) {
    record_bb(drcontext, bb, id);
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
                       OPND_CREATE_INT32(id));
#ifdef TRACE_DEBUG
  dr_fprintf(STDERR, "debug: done\n");
#endif

  return DR_EMIT_DEFAULT;
}

void handle_delete(void* drcontext, void* tag) {
  struct tag_info_t* tag_info;
  bb_id_t id;
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
  save_deletion_event(tb, id);
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
