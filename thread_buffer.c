#include "thread_buffer.h"

size_t tb_available(struct thread_buffer_t* tb) {
  return tb_end(tb) - tb->current;
}

void* tb_end(struct thread_buffer_t* tb) {
  return ((void*)tb) + tb->size;
}

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
  dr_mutex_lock(tb->mutex);
  written = dr_write_file(tb->file, tb + 1, size);
  dr_mutex_unlock(tb->mutex);
  if(written != size) {
    dr_fprintf(STDERR, "fatal: dr_write_file() failed\n");
    dr_exit_process(1);
  }

  // Reset position.
  tb->current = tb + 1;
}

void tb_init(struct thread_buffer_t* tb,
             size_t size,
             file_t file,
             void* mutex,
             thread_id_t thread_id) {
  tb->size = size;
  tb->file = file;
  tb->mutex = mutex;
  tb->thread_id = thread_id;
  tb->current_tlv = NULL;
  tb->current = tb + 1;
}

void tb_tlv(struct thread_buffer_t* tb, uint32_t type) {
  if(tb_available(tb) < sizeof(struct tlv_t)) {
    tb_flush(tb);
  }
  tb->current_tlv = tb->current;
  tb->current_tlv->type = type;
  tb->current = tb->current_tlv + 1;
}

void tb_tlv_cancel(struct thread_buffer_t* tb) {
  tb->current = tb->current_tlv;
  tb->current_tlv = NULL;
}

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
