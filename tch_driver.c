#include "tch_driver.h"

static int __init tch_init(void) {
    int ret;

    g_history_buffer = tch_buffer_create(MAX_HISTORY);
    if (!g_history_buffer) {
        printk(KERN_ERR "TChistory: Failed to allocate history buffer\n");
        return -ENOMEM;
    }

    g_filter_engine = kmalloc(sizeof(filter_engine_t), GFP_KERNEL);
    if (!g_filter_engine) {
        printk(KERN_ERR "TChistory: Failed to allocate filter engine\n");
        tch_buffer_destroy(g_history_buffer);
        return -ENOMEM;
    }

    ret = tch_filter_init(g_filter_engine);
    if (ret < 0) {
        printk(KERN_ERR "TChistory: Failed to initialize filter engine\n");
        kfree(g_filter_engine);
        tch_buffer_destroy(g_history_buffer);
        return ret;
    }

    ret = tch_device_init();
    if (ret < 0) {
        printk(KERN_ERR "TChistory: Failed to initialize device\n");
        tch_filter_destroy(g_filter_engine);
        kfree(g_filter_engine);
        tch_buffer_destroy(g_history_buffer);
        return ret;
    }

    ret = tch_kprobe_init();
    if (ret < 0) {
        printk(KERN_ERR "TChistory: Failed to initialize kprobe\n");
        tch_device_exit();
        tch_filter_destroy(g_filter_engine);
        kfree(g_filter_engine);
        tch_buffer_destroy(g_history_buffer);
        return ret;
    }

    ret = tch_kprobe_start();
    if (ret < 0) {
        printk(KERN_ERR "TChistory: Failed to start kprobe\n");
        tch_kprobe_exit();
        tch_device_exit();
        tch_filter_destroy(g_filter_engine);
        kfree(g_filter_engine);
        tch_buffer_destroy(g_history_buffer);
        return ret;
    }

    printk(KERN_INFO "TChistory: Monitor online. Buffer: %d entries\n", MAX_HISTORY);
    return 0;
}

static void __exit tch_exit(void) {
    tch_kprobe_stop();
    tch_kprobe_exit();
    tch_device_exit();

    if (g_filter_engine) {
        tch_filter_destroy(g_filter_engine);
        kfree(g_filter_engine);
        g_filter_engine = NULL;
    }

    if (g_history_buffer) {
        tch_buffer_destroy(g_history_buffer);
        g_history_buffer = NULL;
    }

    printk(KERN_INFO "TChistory: Monitor offline.\n");
}

module_init(tch_init);
module_exit(tch_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("rainyxin");
MODULE_DESCRIPTION("Terminal Command History Kernel Monitor - Enhanced Version");
MODULE_VERSION("2.0");
