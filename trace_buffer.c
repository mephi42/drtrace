#include <inttypes.h>

#include "crc32.h"
#include "trace_buffer.h"

size_t tb_available(struct trace_buffer_t* tb) {
  return tb_end(tb) - tb->current;
}

void* tb_end(struct trace_buffer_t* tb) {
  return ((void*)tb) + tb->size;
}

void tb_flush(struct trace_buffer_t* tb) {
  size_t size;
  int64 pos;
  size_t written;

  tb_tlv_complete(tb);

  size = tb->current - (void*)&tb->block;
  if(size == sizeof(struct block_t)) {
    // Nothing to do.
    return;
  }
  tb->block.length = (uint32_t)size;
  tb->block.crc32 = 0;
  tb->block.crc32 = crc32((char*)&tb->block, size);

  // Write data.
  dr_mutex_lock(tb->mutex);
  pos = dr_file_tell(tb->file);
  if(pos == -1) {
    dr_fprintf(STDERR, "fatal: dr_file_tell() failed\n");
    dr_exit_process(1);
  }
  dr_fprintf(STDERR,
             "info: flushing tb=%p file-offset=%" PRId64 " size=%u"
             " tb-thread=0x%" PRIx64 " current-thread=0x%" PRIx64 "\n",
             tb,
             pos,
             (unsigned int)size,
             tb->block.thread_id,
             (uint64_t)dr_get_thread_id(dr_get_current_drcontext()));
  written = dr_write_file(tb->file, &tb->block, size);
  dr_mutex_unlock(tb->mutex);
  if(written != size) {
    dr_fprintf(STDERR, "fatal: dr_write_file() failed\n");
    dr_exit_process(1);
  }

  // Reset position.
  tb->current = tb + 1;
}

void tb_init(struct trace_buffer_t* tb,
             size_t size,
             file_t file,
             void* mutex,
             thread_id_t thread_id) {
  tb->size = size;
  tb->file = file;
  tb->mutex = mutex;
  tb->block.thread_id = (uint64_t)thread_id;
  tb->current_tlv = NULL;
  tb->current = tb + 1;
}

void tb_tlv(struct trace_buffer_t* tb, uint32_t type) {
  if(tb_available(tb) < sizeof(struct tlv_t)) {
    tb_flush(tb);
  }
  tb->current_tlv = tb->current;
  tb->current_tlv->type = type;
  tb->current = tb->current_tlv + 1;
}

void tb_tlv_cancel(struct trace_buffer_t* tb) {
  if(tb->current_tlv) {
    tb->current = tb->current_tlv;
    tb->current_tlv = NULL;
  }
}

bool tb_tlv_is(struct trace_buffer_t* tb, uint32_t type) {
  if(tb->current_tlv) {
    return tb->current_tlv->type == type;
  } else {
    return false;
  }
}

void tb_tlv_complete(struct trace_buffer_t* tb) {
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
