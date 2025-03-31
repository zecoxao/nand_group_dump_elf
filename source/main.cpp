#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>

extern "C" {
#include <ps5/kernel.h>
}



#define ENABLE_LOGS 0
#define PC_IP   "192.168.1.3"
#define PC_PORT 5655

#define IP(a, b, c, d) (((a) << 0) + ((b) << 8) + ((c) << 16) + ((d) << 24))

#define NAND_A53IO_OPEN                 0x80046101
#define NAND_A53IO_DISABLE_CONTROLLER   0x80046104

#define PUP_UPDATER_READ_NAND_GROUP     0xC018440A

typedef struct notify_request {
  char useless1[45];
  char message[3075];
} notify_request_t;

extern "C" {
	int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);
}

struct ioctl_readnandgroup_args
{
    uint64_t group_id;
    uint64_t p_out;
    uint64_t size;
};

int g_debug_sock;

int sock;

/*void sock_print(int sock, char *str)
{
	size_t size = 0;

#if ENABLE_LOGS
	size = strlen(str);
	write(sock, str, size);
#endif
}*/

#define printf_notification(fmt, ...) \
{   notify_request_t req; \
	bzero(&req, sizeof req); \
	snprintf(req.message, sizeof req.message, fmt, ##__VA_ARGS__); \
	sceKernelSendNotificationRequest(0, &req, sizeof req, 0); \
} while(0);

int main(){
	
	pid_t pid;
	
	pid = getpid();
	kernel_set_ucred_authid(pid, 0x4801000000000013L);
    
	
	// Jailbreak
    kernel_set_proc_rootdir(getpid(), kernel_get_root_vnode());
	
	int ret;
    //int sock;
    int out_fds[3];
    int a53_fd;
    int pupupdate_fd;
    int zero;
    int written_bytes;
    //char printbuf[128];
    //struct sockaddr_in addr;
    void *out_data;
    uint64_t nand_size;
    
    

    zero         = 0;
    a53_fd       = -1;
    pupupdate_fd = -1;
    out_data     = NULL;
	
	/*
	sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    inet_pton(AF_INET, PC_IP, &addr.sin_addr);
    addr.sin_family = AF_INET;
    addr.sin_len    = sizeof(addr);
    addr.sin_port   = htons(PC_PORT);

    ret = connect(sock, (const struct sockaddr *) &addr, sizeof(addr));
    if (ret < 0) {
        return -1;
    }
	*/
	mkdir("/data/PS5", 0777);

    out_fds[0] = open("/data/PS5/nandgroup0.bin", O_WRONLY | O_CREAT, 0644);
    if (out_fds[0] < 0) {
        printf_notification("[+] failed to open output file (%d)\n", errno);
        //sock_print(sock, printbuf);
        //close(sock);
        return -1;
    }

    out_fds[1] = open("/data/PS5/nandgroup1.bin", O_WRONLY | O_CREAT, 0644);
    if (out_fds[0] < 0) {
        printf_notification("[+] failed to open output file (%d)\n", errno);
        //sock_print(sock, printbuf);
        //close(sock);
        return -1;
    }

    out_fds[2] = open("/data/PS5/nandgroup2.bin", O_WRONLY | O_CREAT, 0644);
    if (out_fds[0] < 0) {
        printf_notification("[+] failed to open output file (%d)\n", errno);
        //sock_print(sock, printbuf);
        //close(sock);
        return -1;
    }
	
	// Open A53IO device to configure NAND
    a53_fd = open("/dev/a53io", 2, 0);
    printf_notification("[+] a53io dev = 0x%x (errno = %d)\n", a53_fd, errno);
    //sock_print(sock, printbuf);
	
	if (a53_fd < 0) {
        printf_notification("[!] failed to open a53 :(\n");
        //sock_print(sock, printbuf);
        goto out;
    }
	
	// Disable the A53 controller, which is necessary to expose NAND to read
    ret = ioctl(a53_fd, NAND_A53IO_DISABLE_CONTROLLER, &zero);
    printf_notification("[+] disable controller = 0x%x (errno = %d)\n", ret, errno);
    //sock_print(sock, printbuf);
	
	// Map buffer for output NAND group data
    out_data = mmap(0, 0x4000000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (out_data == NULL) {
        printf_notification("[!] failed to map memory for nand data (%d) :(\n", errno);
        //sock_print(sock, printbuf);
        goto out;
    }

    // Open pup update FD to do reading
    pupupdate_fd = open("/dev/pup_update0", 2, 0);
    if (pupupdate_fd < 0) {
        printf_notification("[!] failed to open pup_update0 (%d) :(\n",  errno);
        //sock_print(sock, printbuf);
        goto out;
    }

    printf_notification("[+] pup update dev = 0x%x (errno = %d)\n", pupupdate_fd, errno);
    //sock_print(sock, printbuf);
	
	// Max 3 NAND groups
    for (int i = 0; i < 3; i++) {
        memset(out_data, 0, 0x4000000);

        struct ioctl_readnandgroup_args ioc_args = {};
        ioc_args.group_id = i;
        ioc_args.p_out = (uint64_t)out_data;

        // NAND groups have different sizes:
        // group 0 is 0x4000000
        // group 1 is 0x3e00000
        // group 2 is 0x237800 on late revisions
        if (i == 0) {
            nand_size = 0x4000000;
        } else if (i == 1) {
            nand_size = 0x3e00000;
        } else {
            nand_size = 0x237800;
        }

        ioc_args.size = nand_size;

        // Read NAND data
        ret = ioctl(pupupdate_fd, PUP_UPDATER_READ_NAND_GROUP, &ioc_args);
        if (ret != 0) {
            printf_notification("[!] failed to read NAND (%d) :(\n", errno);
            //sock_print(sock, printbuf);
            goto out;
        }

        printf_notification("[+] read nand group %d = %d (errno = %d)\n", i, ret, errno);
        //sock_print(sock, printbuf);

        // Dump to file
        written_bytes = write(out_fds[i], out_data, nand_size);
        if (written_bytes != nand_size) {
            printf_notification("[!] failed to write nand to file, %d != %lu.\n", written_bytes, nand_size);
            //sock_print(sock, printbuf);
            goto out;
        }

        printf_notification("[+] wrote %d bytes...\n", written_bytes);
        //sock_print(sock, printbuf);
    }

    printf_notification("Done!\n");
    //sock_print(sock, printbuf);
	
out:
    if (out_data != NULL)
        munmap(out_data, 0x4000000);

    if (a53_fd >= 0)
        close(a53_fd);

    if (pupupdate_fd >= 0)
        close(pupupdate_fd);

    close(out_fds[0]);
    close(out_fds[1]);
    close(out_fds[2]);
#if ENABLE_LOGS
    //close(sock);
#endif
  
	return 0;
}
