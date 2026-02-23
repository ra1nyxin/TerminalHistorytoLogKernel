#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/time.h>

#define DEVICE_NAME "tch_history"
#define CLASS_NAME "tch"
#define MAX_HISTORY 10000
#define CMD_LEN_MAX 256

typedef struct {
    char cmd[CMD_LEN_MAX];
    uid_t uid;
    unsigned long timestamp;
} cmd_entry_t;

static cmd_entry_t *history_buffer = NULL;
static int head = 0;
static int count = 0;
static DEFINE_SPINLOCK(history_lock);
static int major_number;
static struct class* tch_class = NULL;
static struct device* tch_device = NULL;

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    struct filename *fname = (struct filename *)regs->di;
    unsigned long flags;
    if (!fname || !fname->name) return 0;
    spin_lock_irqsave(&history_lock, flags);
    strncpy(history_buffer[head].cmd, fname->name, CMD_LEN_MAX - 1);
    history_buffer[head].cmd[CMD_LEN_MAX - 1] = '\0';
    history_buffer[head].uid = current_uid().val;
    history_buffer[head].timestamp = ktime_get_real_seconds();
    head = (head + 1) % MAX_HISTORY;
    if (count < MAX_HISTORY) count++;
    spin_unlock_irqrestore(&history_lock, flags);
    return 0;
}

static struct kprobe kp = {
    .symbol_name = "do_execve",
    .pre_handler = handler_pre,
};

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    int i, bytes_read = 0, start_pos;
    char *temp_buf;
    unsigned long flags;
    const int entry_size = 512;
    if (!uid_eq(current_uid(), GLOBAL_ROOT_UID)) return -EACCES;
    if (*offset > 0) return 0;
    temp_buf = kmalloc(entry_size, GFP_KERNEL);
    if (!temp_buf) return -ENOMEM;
    spin_lock_irqsave(&history_lock, flags);
    start_pos = (count < MAX_HISTORY) ? 0 : head;
    for (i = 0; i < count; i++) {
        int idx = (start_pos + i) % MAX_HISTORY;
        struct tm result_tm;
        int msg_len;
        time64_to_tm(history_buffer[idx].timestamp, 0, &result_tm);
        msg_len = snprintf(temp_buf, entry_size, "[%04ld-%02d-%02d %02d:%02d:%02d] UID:%d CMD:%s\n",
            (long)result_tm.tm_year + 1900, result_tm.tm_mon + 1, result_tm.tm_mday, 
            result_tm.tm_hour, result_tm.tm_min, result_tm.tm_sec,
            history_buffer[idx].uid, history_buffer[idx].cmd);
        if (bytes_read + msg_len > len) break;
        if (copy_to_user(buffer + bytes_read, temp_buf, msg_len)) {
            spin_unlock_irqrestore(&history_lock, flags);
            kfree(temp_buf);
            return -EFAULT;
        }
        bytes_read += msg_len;
    }
    spin_unlock_irqrestore(&history_lock, flags);
    kfree(temp_buf);
    *offset += bytes_read;
    return bytes_read;
}

static struct file_operations fops = { .read = dev_read, .owner = THIS_MODULE };

static int __init tch_init(void) {
    int ret;
    history_buffer = vmalloc(sizeof(cmd_entry_t) * MAX_HISTORY);
    if (!history_buffer) return -ENOMEM;
    memset(history_buffer, 0, sizeof(cmd_entry_t) * MAX_HISTORY);
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) { vfree(history_buffer); return major_number; }
    tch_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(tch_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        vfree(history_buffer);
        return PTR_ERR(tch_class);
    }
    tch_device = device_create(tch_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(tch_device)) {
        class_destroy(tch_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        vfree(history_buffer);
        return PTR_ERR(tch_device);
    }
    ret = register_kprobe(&kp);
    if (ret < 0) {
        device_destroy(tch_class, MKDEV(major_number, 0));
        class_destroy(tch_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        vfree(history_buffer);
        return ret;
    }
    printk(KERN_INFO "TChistory: Monitor online. Buffer: %d entries\n", MAX_HISTORY);
    return 0;
}

static void __exit tch_exit(void) {
    unregister_kprobe(&kp);
    device_destroy(tch_class, MKDEV(major_number, 0));
    class_destroy(tch_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    vfree(history_buffer);
    printk(KERN_INFO "TChistory: Monitor offline.\n");
}

module_init(tch_init);
module_exit(tch_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("rainyxin");
MODULE_DESCRIPTION("Terminal Command History Kernel Monitor");
