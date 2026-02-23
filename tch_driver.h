#ifndef TCH_DRIVER_H
#define TCH_DRIVER_H

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
#include <linux/mutex.h>
#include <linux/time.h>
#include <linux/types.h>

#define DEVICE_NAME "tch_history"
#define CLASS_NAME "tch"
#define MAX_HISTORY 10000
#define CMD_LEN_MAX 256
#define ARGS_LEN_MAX 4096
#define COMM_LEN_MAX 16
#define MAX_FILTER_RULES 64

typedef struct {
    char cmd[CMD_LEN_MAX];
    char args[ARGS_LEN_MAX];
    char comm[COMM_LEN_MAX];
    uid_t uid;
    pid_t pid;
    pid_t ppid;
    unsigned long timestamp;
    unsigned int remote_ip;
    unsigned short remote_port;
} cmd_entry_t;

typedef enum {
    FILTER_MODE_NONE,
    FILTER_MODE_WHITELIST,
    FILTER_MODE_BLACKLIST
} filter_mode_t;

typedef struct {
    char keyword[CMD_LEN_MAX];
    int enabled;
} filter_rule_t;

typedef struct {
    cmd_entry_t *entries;
    int head;
    int count;
    int max_size;
    spinlock_t lock;
} history_buffer_t;

typedef struct {
    filter_rule_t rules[MAX_FILTER_RULES];
    int rule_count;
    filter_mode_t mode;
    pid_t target_pid;
    uid_t target_uid;
    int enable_pid_filter;
    int enable_uid_filter;
    struct mutex filter_lock;
} filter_engine_t;

extern history_buffer_t *tch_buffer_create(int max_size);
extern void tch_buffer_destroy(history_buffer_t *buffer);
extern int tch_buffer_push(history_buffer_t *buffer, const cmd_entry_t *entry);
extern int tch_buffer_pop(history_buffer_t *buffer, cmd_entry_t *entry);
extern int tch_buffer_get_count(history_buffer_t *buffer);
extern int tch_buffer_read_all(history_buffer_t *buffer, char *user_buf, size_t len);

extern int tch_filter_init(filter_engine_t *filter);
extern void tch_filter_destroy(filter_engine_t *filter);
extern int tch_filter_add_rule(filter_engine_t *filter, const char *keyword);
extern int tch_filter_remove_rule(filter_engine_t *filter, const char *keyword);
extern int tch_filter_set_mode(filter_engine_t *filter, filter_mode_t mode);
extern int tch_filter_check(filter_engine_t *filter, const cmd_entry_t *entry);
extern int tch_filter_set_pid(filter_engine_t *filter, pid_t pid);
extern int tch_filter_set_uid(filter_engine_t *filter, uid_t uid);

extern int tch_kprobe_init(void);
extern void tch_kprobe_exit(void);
extern int tch_kprobe_start(void);
extern void tch_kprobe_stop(void);

extern int tch_device_init(void);
extern void tch_device_exit(void);

#endif
