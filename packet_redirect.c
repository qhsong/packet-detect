#include <stdio.h>
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <monetary.h>
#include <locale.h>
#include <linux/tcp.h>

#include "pfring.h"
#include "pfutils.c"

#include "thrid-party/sort.c"
#include "third-party/node.c"
#include "third-party/ahocorasick.c"

#include "common.h"

#define SEND_DEV "eth1"
#define RECV_DEV "eth2"
#define SNAPLEN 1500

char d_mac_address[6];	//destnation mac
static struct timeval startTime;
static int32_t thiszone;
struct app_stats *stats;
int reforge_mac;
pfring *pdsend,*pdrecv;
int stop_pck;

void sigproc(int sig) {
	static int callled = 0;
	fprintf(stderr,"Leaving...\n");
	if(called) {
		return;
	}else{
		called = 1;
	}
	stop_pck = 1;
	pfring_breakloop(pdsend);
}


void ProcessPacket(const struct pfring_pkthdr *h,
					const u_char *p,const u_char *user_bytes) {
	return ;
}

void printHelp() {
	printf("pckred \n\n");
	printf("-h 				Print Help\n\n");
	printf("-s <device> 	Send device name\n\n");
	printf("-r <device> 	Recv device name\n\n");
	printf("-m <mac_addr>	Route mac address\n\n");
	exit(0);
}

int init(char *recv_dev,char *send_dev) {
	u_int32_t flags,version;
	int rc;
	char path[256] = {0};

	flags = PF_RING_PROMISC|PF_RING_LONG_HEADER|PF_RING_DNA_SYMMETRIC_RSS;
	pdrecv = pfring_open(recv_dev,SNAPLEN,flags);
	if(pdrecv == NULL) {
		fprintf(stderr,"pfring_open error [%s] (pf_ring not loaded or perhaps you use quick mode and have already a socket bound to %s ?)\n",strerror(errno),recv_dev);
		return -1;
	}
	
	pdsend = pfring(send_dev, SNAPLEN ,0);
	if(pdsend == NULL) {
		printf("pfring_open %s error, [%s]\n",send_dev,strerror(errno));
		return -1;
	}

	if(!pdsend->send && pdsend->send_ifindex ) {
		printf("send setting error!");
		return -1;
	}

	pfring_set_application_name(pdrecv,"pktred");
	pfring_set_application_name(pdsend,"pktred");
	pfring_version(pdrecv,&version);

	printf("Using PF_RING v.%d.%d.%d\n",
			(version & 0xFFFF0000) >> 16,
			(version & 0x0000FF00) >> 8,
			version & 0x000000FF);
	printf("Recv device RX channels: %d",pfring_get_num_rx_channels(pdrecv));

	pfring_set_direction(pdrecv ,rx_and_tx_direction);
	if((rc = pfring_set_socket_mode(pdrecv,recv_only_mode)) != 0) {
		fprintf(stderr,"Set recv pfring_set_socket_mode return [rc=%d]\n",rc);
		return -1;
	}
	
	if((rc = pfring_set_socket_mode(pdsend,send_only_mode)) !=0 ) {
		fprintf(stderr,"Set send pfring_set_socket_mode return [rc=%d]\n",rc);
		return -1;
	}

	if(pfring_get_appl_stats_file_name(pdrecv,path,sizeof(path)) != NULL) {
		fprintf(stderr,"Dumping statistics on %s\n",path);
	}
	
	stats = (struct app_stats *)malloc(sizeof(struct app_stats));

	return 0;
}


int main(int argc,char **argv) {
	char *send_device = NULL,*recv_device = NULL;
	u_int mac_add[6];
	thiszone = gmt_to_local(0);
	
	int i;
	reforge_mac = 0;
	stop_pck = 0;

	while((c= getopt(argc,argv,"s:r:m:h")) != '?') {
		if((c == 255) || (c == -1)) break;

		switch(c) {
			case 'h':
				printHelp();
				return 0;
				break;
			case 's':
				send_device = strdup(optarg);
				break;
			case 'r':
				recv_device = strdup(optarg);
				break;
			case 'm':
				if(sscanf(optarg,"%02X:%02X:%02X:%02X:%02X:%02X",&mac_add[0],&mac_add[1],&mac_add[2],&mac_add[3],&mac_add[4],&mac_add[5]) != 6 ) {
					printf("Invalid MAC address format (XX:XX:XX:XX:XX:XX)\n");
					return 0;
				}
				for(i=0 ; i<6 ;i++) {
					d_mac_address[i] = mac_add[i];
				}
				break;
		}
	}
	
	bind2node(1);	//bind it in 1 core;
	if(init(recv_dev,send_dev) != 0) {
		printf("####init error!####");
		return -1;
	}

	signal(SIGINT ,sigproc);
	singal(SIGTERM ,sigproc);
	singal(SIGINT ,sigproc);
	
	if(pfring_enable_ring(pdsend) != 0 && pfring_enable_ring(pdrecv) != 0) {
		printf("Unable to enable ring \n");
		pfring_close(pdsend);
		pdsend = NULL;
		pfring_close(pdrecv);
		pdrecv = NULL;
		return -1;
	}

	pfring_loop(pdrecv,ProressPacket,(u_char *)NULL,wait_for_packet);

}
