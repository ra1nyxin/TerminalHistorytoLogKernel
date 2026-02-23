#include "tch_driver.h"

extern history_buffer_t *g_history_buffer;
extern filter_engine_t *g_filter_engine;

static int major_number;
static struct class *tch_class = NULL;
static struct device *tch_device = NULL;
static struct device *tch_device_ctl = NULL;

#define CTL_MAGIC 'T'
#define CTL_ADD_FILTER _IOW(CTL_MAGIC, 1, char *)
#define CTL_REM_FILTER _IOW(CTL_MAGIC, 2, char *)
#define CTL_SET_MODE _IOW(CTL_MAGIC, 3, int)
#define CTL_SET_PID _IOW(CTL_MAGIC, 4, int)
#define CTL_SET_UID _IOW(CTL_MAGIC, 5, int)
#define CTL_CLEAR _IO(CTL_MAGIC, 6)

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    int bytes_read;

    if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
        return -EACCES;

    if (*offset > 0)
        return 0;

    if (!g_history_buffer)
        return -ENODEV;

    bytes_read = tch_buffer_read_all(g_history_buffer, buffer, len);
    if (bytes_read < 0)
        return bytes_read;

    *offset += bytes_read;
    return bytes_read;
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
    char cmd[64];

    if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
        return -EACCES;

    if (len >= sizeof(cmd))
        len = sizeof(cmd) - 1;

    if (copy_from_user(cmd, buffer, len))
        return -EFAULT;

    cmd[len] = '\0';

    if (strncmp(cmd, "clear", 5) == 0) {
        if (g_history_buffer) {
            unsigned long flags;
            spin_lock_irqsave(&g_history_buffer->lock, flags);
            g_history_buffer->head = 0;
            g_history_buffer->count = 0;
            spin_unlock_irqrestore(&g_history_buffer->lock, flags);
        }
        return len;
    }

    return len;
}

static long dev_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {
    char keyword[CMD_LEN_MAX];
    int mode, value;

    if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
        return -EACCES;

    if (!g_filter_engine)
        return -ENODEV;

    switch (cmd) {
    case CTL_ADD_FILTER:
        if (copy_from_user(keyword, (char __user *)arg, CMD_LEN_MAX))
            return -EFAULT;
        return tch_filter_add_rule(g_filter_engine, keyword);

    case CTL_REM_FILTER:
        if (copy_from_user(keyword, (char __user *)arg, CMD_LEN_MAX))
            return -EFAULT;
        return tch_filter_remove_rule(g_filter_engine, keyword);

    case CTL_SET_MODE:
        if (copy_from_user(&mode, (int __user *)arg, sizeof(int)))
            return -EFAULT;
        return tch_filter_set_mode(g_filter_engine, (filter_mode_t)mode);

    case CTL_SET_PID:
        if (copy_from_user(&value, (int __user *)arg, sizeof(int)))
            return -EFAULT;
        return tch_filter_set_pid(g_filter_engine, (pid_t)value);

    case CTL_SET_UID:
        if (copy_from_user(&value, (int __user *)arg, sizeof(int)))
            return -EFAULT;
        return tch_filter_set_uid(g_filter_engine, (uid_t)value);

    case CTL_CLEAR:
        if (g_history_buffer) {
            unsigned long flags;
            spin_lock_irqsave(&g_history_buffer->lock, flags);
            g_history_buffer->head = 0;
            g_history_buffer->count = 0;
            spin_unlock_irqrestore(&g_history_buffer->lock, flags);
        }
        return 0;

    default:
        return -EINVAL;
    }
}

static int dev_open(struct inode *inode, struct file *file) {
    return 0;
}

static int dev_release(struct inode *inode, struct file *file) {
    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = dev_read,
    .write = dev_write,
    .unlocked_ioctl = dev_ioctl,
    .open = dev_open,
    .release = dev_release,
};

static ssize_t ctl_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    int bytes_read = 0;

    if (*offset > 0)
        return 0;

    if (!g_filter_engine)
        return -ENODEV;

    bytes_read = snprintf(buffer, len,
        "Filter Status:\n"
        "  Mode: %d (0=None, 1=Whitelist, 2=Blacklist)\n"
        "  Rules: %d\n"
        "  PID Filter: %s (pid=%d)\n"
        "  UID Filter: %s (uid=%d)\n",
        g_filter_engine->mode,
        g_filter_engine->rule_count,
        g_filter_engine->enable_pid_filter ? "Enabled" : "Disabled",
        g_filter_engine->target_pid,
        g_filter_engine->enable_uid_filter ? "Enabled" : "Disabled",
        g_filter_engine->target_uid);

    *offset += bytes_read;
    return bytes_read;
}

static struct file_operations ctl_fops = {
    .owner = THIS_MODULE,
    .read = ctl_read,
};

int tch_device_init(void) {
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ERR "TChistory: Failed to register character device\n");
        return major_number;
    }

    tch_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(tch_class)) {
        printk(KERN_ERR "TChistory: Failed to create device class\n");
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(tch_class);
    }

    tch_device = device_create(tch_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(tch_device)) {
        printk(KERN_ERR "TChistory: Failed to create device\n");
        class_destroy(tch_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(tch_device);
    }

    tch_device_ctl = device_create(tch_class, NULL, MKDEV(major_number, 1), NULL, DEVICE_NAME "_ctl");
    if (IS_ERR(tch_device_ctl)) {
        printk(KERN_WARNING "TChistory: Failed to create control device, continuing without it\n");
        tch_device_ctl = NULL;
    }

    printk(KERN_INFO "TChistory: Device created with major number %d\n", major_number);
    return 0;
}

void tch_device_exit(void) {
    if (tch_device_ctl)
        device_destroy(tch_class, MKDEV(major_number, 1));

    if (tch_device)
        device_destroy(tch_class, MKDEV(major_number, 0));

    if (tch_class)
        class_destroy(tch_class);

    unregister_chrdev(major_number, DEVICE_NAME);

    printk(KERN_INFO "TChistory: Device unregistered\n");
}

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("rainyxin");
MODULE_DESCRIPTION("TChistory Device Module");
