# TChistory - Terminal Command History Kernel Monitor

A Linux kernel module for monitoring terminal command execution in real-time.

## 功能特性

- **系统调用监控**：通过 kprobe 钩取 do_execve 系统调用，捕获所有命令执行
- **完整参数记录**：不仅记录执行的程序名，还记录完整的命令行参数
- **进程溯源**：记录 PID、PPID 和进程名，便于还原命令执行链
- **过滤引擎**：支持白名单/黑名单模式，可按关键字或 UID/PID 过滤
- **环形缓冲区**：使用内存高效的环形缓冲区设计，最多记录 10000 条历史
- **字符设备接口**：通过 /dev/tch_history 设备读取命令历史

## 构建

```bash
make
```

需要安装内核头文件：

```bash
# Debian/Ubuntu
sudo apt-get install linux-headers-$(uname -r)

# RHEL/CentOS
sudo yum install kernel-devel-$(uname -r)
```

## 使用方法

### 加载模块

```bash
sudo insmod tch_driver.ko
```

### 读取历史记录

```bash
# 只能由 root 用户读取
sudo cat /dev/tch_history
```

输出格式：

```
[2024-01-15 14:30:25] PID:1234 PPID:1000 UID:0 COMM:bash CMD:/usr/bin/ls ARGS:-la /home
```

### 控制接口

通过 ioctl 进行过滤控制：

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define DEVICE_NAME "/dev/tch_history"
#define CTL_MAGIC 'T'
#define CTL_ADD_FILTER _IOW(CTL_MAGIC, 1, char *)
#define CTL_SET_MODE _IOW(CTL_MAGIC, 3, int)

int main() {
    int fd = open(DEVICE_NAME, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // 添加过滤关键字
    ioctl(fd, CTL_ADD_FILTER, "curl");
    ioctl(fd, CTL_ADD_FILTER, "wget");

    // 设置为黑名单模式 (2)，过滤包含上述关键字的命令
    int mode = 2;
    ioctl(fd, CTL_SET_MODE, &mode);

    close(fd);
    return 0;
}
```

### 卸载模块

```bash
sudo rmmod tch_driver
```

## 技术细节

### 数据结构

每个命令条目包含：

- `cmd`: 执行的程序路径
- `args`: 完整的命令行参数
- `comm`: 进程名
- `pid`: 进程 ID
- `ppid`: 父进程 ID
- `uid`: 用户 ID
- `timestamp`: 执行时间戳

### 模块化设计

代码分为多个源文件：

- `tch_driver.c` - 主模块入口
- `tch_buffer.c` - 环形缓冲区实现
- `tch_kprobe.c` - kprobe 钩取逻辑
- `tch_device.c` - 字符设备接口
- `tch_filter.c` - 过滤引擎

## 许可证

MIT License

## 作者

rainyxin
