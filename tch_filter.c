#include "tch_driver.h"

int tch_filter_init(filter_engine_t *filter) {
    int i;

    if (!filter)
        return -EINVAL;

    memset(filter->rules, 0, sizeof(filter->rules));
    filter->rule_count = 0;
    filter->mode = FILTER_MODE_NONE;
    filter->target_pid = -1;
    filter->target_uid = -1;
    filter->enable_pid_filter = 0;
    filter->enable_uid_filter = 0;
    mutex_init(&filter->filter_lock);

    for (i = 0; i < MAX_FILTER_RULES; i++)
        filter->rules[i].enabled = 0;

    return 0;
}

void tch_filter_destroy(filter_engine_t *filter) {
    if (!filter)
        return;

    mutex_destroy(&filter->filter_lock);
}

int tch_filter_add_rule(filter_engine_t *filter, const char *keyword) {
    int i;

    if (!filter || !keyword)
        return -EINVAL;

    mutex_lock(&filter->filter_lock);

    if (filter->rule_count >= MAX_FILTER_RULES) {
        mutex_unlock(&filter->filter_lock);
        return -ENOSPC;
    }

    for (i = 0; i < MAX_FILTER_RULES; i++) {
        if (!filter->rules[i].enabled) {
            strncpy(filter->rules[i].keyword, keyword, CMD_LEN_MAX - 1);
            filter->rules[i].keyword[CMD_LEN_MAX - 1] = '\0';
            filter->rules[i].enabled = 1;
            filter->rule_count++;
            mutex_unlock(&filter->filter_lock);
            return 0;
        }
    }

    mutex_unlock(&filter->filter_lock);
    return -ENOSPC;
}

int tch_filter_remove_rule(filter_engine_t *filter, const char *keyword) {
    int i;

    if (!filter || !keyword)
        return -EINVAL;

    mutex_lock(&filter->filter_lock);

    for (i = 0; i < MAX_FILTER_RULES; i++) {
        if (filter->rules[i].enabled &&
            strncmp(filter->rules[i].keyword, keyword, CMD_LEN_MAX) == 0) {
            filter->rules[i].enabled = 0;
            filter->rule_count--;
            mutex_unlock(&filter->filter_lock);
            return 0;
        }
    }

    mutex_unlock(&filter->filter_lock);
    return -ENOENT;
}

int tch_filter_set_mode(filter_engine_t *filter, filter_mode_t mode) {
    if (!filter)
        return -EINVAL;

    mutex_lock(&filter->filter_lock);
    filter->mode = mode;
    mutex_unlock(&filter->filter_lock);

    return 0;
}

int tch_filter_set_pid(filter_engine_t *filter, pid_t pid) {
    if (!filter)
        return -EINVAL;

    mutex_lock(&filter->filter_lock);
    filter->target_pid = pid;
    filter->enable_pid_filter = (pid > 0) ? 1 : 0;
    mutex_unlock(&filter->filter_lock);

    return 0;
}

int tch_filter_set_uid(filter_engine_t *filter, uid_t uid) {
    if (!filter)
        return -EINVAL;

    mutex_lock(&filter->filter_lock);
    filter->target_uid = uid;
    filter->enable_uid_filter = (uid != (uid_t)-1) ? 1 : 0;
    mutex_unlock(&filter->filter_lock);

    return 0;
}

int tch_filter_check(filter_engine_t *filter, const cmd_entry_t *entry) {
    int i, matched = 0;

    if (!filter || !entry)
        return 1;

    if (filter->enable_pid_filter && filter->target_pid > 0) {
        if (entry->pid != filter->target_pid)
            return 0;
    }

    if (filter->enable_uid_filter && filter->target_uid != (uid_t)-1) {
        if (entry->uid != filter->target_uid)
            return 0;
    }

    if (filter->mode == FILTER_MODE_NONE || filter->rule_count == 0)
        return 1;

    mutex_lock(&filter->filter_lock);

    for (i = 0; i < MAX_FILTER_RULES; i++) {
        if (filter->rules[i].enabled) {
            if (strstr(entry->cmd, filter->rules[i].keyword) ||
                strstr(entry->args, filter->rules[i].keyword)) {
                matched = 1;
                break;
            }
        }
    }

    mutex_unlock(&filter->filter_lock);

    if (filter->mode == FILTER_MODE_BLACKLIST)
        return matched ? 0 : 1;
    else if (filter->mode == FILTER_MODE_WHITELIST)
        return matched ? 1 : 0;

    return 1;
}

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("rainyxin");
MODULE_DESCRIPTION("TChistory Filter Module");
