## psaudit


通过Linux netlink *NETLINK_CONNECTOR* 协议实时进行监控本机进程情况。

当前维度： Linux NETLINK_CONNECTOR ->  execve -> pid -> pid info
之前研究测试用的，方便输出安全规则。

获取的信息

| 参数 | 含义 | 来源|
| :---: | --- |---|
|  **name**   |                    name                     |   /proc/PID/status,Name   |
|   **cmd**   |                     Cmd                     |     /proc/PID/cmdline     |
|   **pid**   |                 process ID                  |       netlink Exec        |
|   **state**   |                  state                      |    /proc/PID/status,state | 
|  **tgid**   |               thread group ID               |   /proc/PID/status,Tgid   |
|   **uid**   |             user ID(进程执行者)             |  /proc/PID/status,Uid[0]  |
|  **euid**   | effective user ID(进程执行对文件的访问权限) |  /proc/PID/status,Uid[1]  |
|  **suid**   |             saved set user ID(副本)             |  /proc/PID/status,Uid[2]  |
|  **fsuid**  |             file system user ID             |  /proc/PID/status,Uid[3]  |
|   **gid**   |                  group ID                   |  /proc/PID/status,Gid[0]  |
|  **egid**   |             effective group ID              |  /proc/PID/status,Gid[1]  |
|  **sgid**   |               saved group ID                |  /proc/PID/status,Gid[2]  |
|  **fsgid**  |            file system group ID             |  /proc/PID/status,Gid[3]  |
|   **cwd**   |                     Cwd                     |   /proc/PID/environ,PWD   |
|   **exe**   |                     Exe                     | /proc/PID/exe (read link) |
|  **ppid**   |              parent process ID              |   /proc/PID/status,PPid   |
| **p_name**  |                  ppid name                  |  /proc/PPID/status,name   |
|  **p_uid**  |                  ppid uid                   | /proc/PPID/status,Uid[0]  |
|  **p_cmd**  |                  ppid cmd                   |    /proc/PPID/cmdline     |
| **fd_info** |                   fd info                   |    /proc/PID/fd/[0-9]*    |
|**sock_info**|               fd to socket info             |          /proc/net        |

