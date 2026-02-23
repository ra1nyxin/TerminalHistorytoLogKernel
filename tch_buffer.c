#include "tch_driver.h"

history_buffer_t *g_history_buffer = NULL;
filter_engine_t *g_filter_engine = NULL;

EXPORT_SYMBOL(g_history_buffer);
EXPORT_SYMBOL(g_filter_engine);

history_buffer_t *tch_buffer_create(int max_size) {
    history_buffer_t *buffer;

    if (max_size <= 0)
        return NULL;

    buffer = kmalloc(sizeof(history_buffer_t), GFP_KERNEL);
    if (!buffer)
        return NULL;

    buffer->entries = vmalloc(sizeof(cmd_entry_t) * max_size);
    if (!buffer->entries) {
        kfree(buffer);
        return NULL;
    }

    memset(buffer->entries, 0, sizeof(cmd_entry_t) * max_size);
    buffer->head = 0;
    buffer->count = 0;
    buffer->max_size = max_size;
    spin_lock_init(&buffer->lock);

    return buffer;
}

void tch_buffer_destroy(history_buffer_t *buffer) {
    if (!buffer)
        return;

    if (buffer->entries)
        vfree(buffer->entries);

    kfree(buffer);
}

int tch_buffer_push(history_buffer_t *buffer, const cmd_entry_t *entry) {
    unsigned long flags;

    if (!buffer || !entry)
        return -EINVAL;

    spin_lock_irqsave(&buffer->lock, flags);

    memcpy(&buffer->entries[buffer->head], entry, sizeof(cmd_entry_t));
    buffer->head = (buffer->head + 1) % buffer->max_size;

    if (buffer->count < buffer->max_size)
        buffer->count++;

    spin_unlock_irqrestore(&buffer->lock, flags);

    return 0;
}

int tch_buffer_pop(history_buffer_t *buffer, cmd_entry_t *entry) {
    unsigned long flags;
    int tail;

    if (!buffer || !entry)
        return -EINVAL;

    spin_lock_irqsave(&buffer->lock, flags);

    if (buffer->count == 0) {
        spin_unlock_irqrestore(&buffer->lock, flags);
        return -ENODATA;
    }

    tail = (buffer->head - buffer->count + buffer->max_size) % buffer->max_size;
    memcpy(entry, &buffer->entries[tail], sizeof(cmd_entry_t));
    buffer->count--;

    spin_unlock_irqrestore(&buffer->lock, flags);

    return 0;
}

int tch_buffer_get_count(history_buffer_t *buffer) {
    int count;
    unsigned long flags;

    if (!buffer)
        return -EINVAL;

    spin_lock_irqsave(&buffer->lock, flags);
    count = buffer->count;
    spin_unlock_irqrestore(&buffer->lock, flags);

    return count;
}

int tch_buffer_read_all(history_buffer_t *buffer, char *user_buf, size_t len) {
    unsigned long flags;
    int i, bytes_read = 0, start_pos;
    char *temp_buf;
    const int entry_size = 1024;

    if (!buffer || !user_buf)
        return -EINVAL;

    if (len == 0)
        return 0;

    temp_buf = kmalloc(entry_size, GFP_KERNEL);
    if (!temp_buf)
        return -ENOMEM;

    spin_lock_irqsave(&buffer->lock, flags);

    if (buffer->count == 0) {
        spin_unlock_irqrestore(&buffer->lock, flags);
        kfree(temp_buf);
        return 0;
    }

    start_pos = (buffer->count < buffer->max_size) ? 0 : buffer->head;

    for (i = 0; i < buffer->count; i++) {
        int idx = (start_pos + i) % buffer->max_size;
        struct tm result_tm;
        int msg_len;

        time64_to_tm(buffer->entries[idx].timestamp, 0, &result_tm);

        msg_len = snprintf(temp_buf, entry_size,
            "[%04ld-%02d-%02d %02d:%02d:%02d] PID:%d PPID:%d UID:%d COMM:%s CMD:%s ARGS:%s\n",
            (long)result_tm.tm_year + 1900, result_tm.tm_mon + 1, result_tm.tm_mday,
            result_tm.tm_hour, result_tm.tm_min, result_tm.tm_sec,
            buffer->entries[idx].pid,
            buffer->entries[idx].ppid,
            buffer->entries[idx].uid,
            buffer->entries[idx].comm,
            buffer->entries[idx].cmd,
            buffer->entries[idx].args);

        if (bytes_read + msg_len > len)
            break;

        if (copy_to_user(user_buf + bytes_read, temp_buf, msg_len)) {
            spin_unlock_irqrestore(&buffer->lock, flags);
            kfree(temp_buf);
            return -EFAULT;
        }
        bytes_read += msg_len;
    }

    spin_unlock_irqrestore(&buffer->lock, flags);
    kfree(temp_buf);

    return bytes_read;
}

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("rainyxin");
MODULE_DESCRIPTION("TChistory Buffer Module");
