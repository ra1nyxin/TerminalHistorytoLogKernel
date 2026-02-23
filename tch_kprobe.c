#include "tch_driver.h"

extern history_buffer_t *g_history_buffer;
extern filter_engine_t *g_filter_engine;

static struct kprobe kp_execve;
static int kprobe_registered = 0;

static int handler_execve(struct kprobe *p, struct pt_regs *regs) {
    cmd_entry_t entry;
    struct filename *fname;
    const char __user *const __user *argv;
    int i, offset = 0;

    memset(&entry, 0, sizeof(entry));

    fname = (struct filename *)regs->di;
    argv = (const char __user *const __user *)regs->si;

    if (fname && fname->name) {
        strncpy(entry.cmd, fname->name, CMD_LEN_MAX - 1);
        entry.cmd[CMD_LEN_MAX - 1] = '\0';
    }

    if (argv) {
        char tmp[ARGS_LEN_MAX];
        for (i = 0; i < 64 && offset < ARGS_LEN_MAX - 1; i++) {
            const char __user *str;
            int len;

            if (get_user(str, argv + i))
                break;
            if (!str)
                break;

            memset(tmp, 0, sizeof(tmp));
            len = strncpy_from_user(tmp, str, sizeof(tmp) - 1);
            if (len < 0)
                break;
            if (len == 0)
                continue;

            if (offset + len + 2 > ARGS_LEN_MAX)
                break;

            if (offset > 0) {
                entry.args[offset++] = ' ';
            }

            strncat(entry.args + offset, tmp, ARGS_LEN_MAX - offset - 1);
            offset += strlen(tmp);
        }
    }

    entry.uid = current_uid().val;
    entry.pid = current->pid;
    entry.ppid = task_ppid_nr(current);
    entry.timestamp = ktime_get_real_seconds();

    strncpy(entry.comm, current->comm, COMM_LEN_MAX - 1);
    entry.comm[COMM_LEN_MAX - 1] = '\0';

    entry.remote_ip = 0;
    entry.remote_port = 0;

    if (g_filter_engine) {
        if (!tch_filter_check(g_filter_engine, &entry))
            return 0;
    }

    if (g_history_buffer) {
        tch_buffer_push(g_history_buffer, &entry);
    }

    return 0;
}

int tch_kprobe_init(void) {
    memset(&kp_execve, 0, sizeof(kp_execve));
    kp_execve.symbol_name = "do_execve";
    kp_execve.pre_handler = handler_execve;
    return 0;
}

void tch_kprobe_exit(void) {
    if (kprobe_registered) {
        unregister_kprobe(&kp_execve);
        kprobe_registered = 0;
    }
}

int tch_kprobe_start(void) {
    int ret;

    ret = register_kprobe(&kp_execve);
    if (ret < 0) {
        printk(KERN_ERR "TChistory: Failed to register kprobe on do_execve: %d\n", ret);
        return ret;
    }

    kprobe_registered = 1;
    printk(KERN_INFO "TChistory: Kprobe registered on do_execve\n");
    return 0;
}

void tch_kprobe_stop(void) {
    if (kprobe_registered) {
        unregister_kprobe(&kp_execve);
        kprobe_registered = 0;
        printk(KERN_INFO "TChistory: Kprobe unregistered\n");
    }
}

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("rainyxin");
MODULE_DESCRIPTION("TChistory Kprobe Module");
