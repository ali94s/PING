#include<sys/socket.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<unistd.h>
#include<signal.h>
#include<arpa/inet.h>
#include<errno.h>
#include<sys/time.h>
#include<stdio.h>
#include<string.h>
#include<netdb.h>
#include<pthread.h>


#define TT printf("%d\n",__LINE__)


typedef struct pingm_packet
{
	struct timeval tv_begin;
	struct timeval tv_end;
	short seq;
	int flag;
}pingm_packet;
static pingm_packet pingpacket[128];

static void icmp_sigint(int signo);
static struct timeval icmp_tvsub(struct timeval end,struct timeval begin);
static void* icmp_send(void *argv);
static void* icmp_recv(void *argv);
static pingm_packet *icmp_findpacket(int seq);
static void icmp_pack(struct icmp *icnph,int seq,struct timeval *tv,int length);
static unsigned short icmp_cksum(unsigned char *data,int len);
static int icmp_unpack(char *buf,int len);


#define K 4096
#define SIZE 72

static unsigned char send_buf[SIZE];
static unsigned char recv_buf[K];
static struct sockaddr_in dest;
static int rawsock=0;
pid_t pid=0;
static int alive=0;
static short packet_send=0;
static short packet_recv=0;
static char dest_str[80];
static struct timeval tv_begin,tv_end,tv_interval;

static void icmp_usage()
{
	printf("ping aaa.bbb.ccc.dddd\n");
}


static void icmp_sigint(int signo)
{
	alive=0;
	gettimeofday(&tv_end,NULL);
	tv_interval=icmp_tvsub(tv_end,tv_begin);

	return;
}

static struct timeval icmp_tvsub(struct timeval end,struct timeval begin)
{
	struct timeval tv;

	tv.tv_sec=end.tv_sec-begin.tv_sec;
	tv.tv_usec=end.tv_usec-begin.tv_usec;

	if(tv.tv_usec<0)
	{
		tv.tv_sec--;
		tv.tv_usec+=1000000;
	}

	return tv;
}

static void* icmp_send(void *argv)
{
/////////////////////////////////////////////////////////
	//printf("icmp_send\n");

	gettimeofday(&tv_begin,NULL);

	while(alive)
	{
		int size=0;
		struct timeval tv;
		gettimeofday(&tv,NULL);

		pingm_packet *packet=icmp_findpacket(-1);
		
		if(packet!=NULL)
		{
			packet->seq=packet_send;
			packet->flag=1;
			gettimeofday(&packet->tv_begin,NULL);
		}

		icmp_pack((struct icmp*)send_buf,packet_send,&tv,64);
		size=sendto(rawsock,send_buf,64,0,(struct sockaddr*)&dest,sizeof(dest));

		if(size<0)
		{
			perror("sendto(0");
			continue;
		}
		packet_send++;
		sleep(1);
	}
}


static void* icmp_recv(void *argv)
{
///////////////////////////////////////////////
	//printf("icmp_recv\n");
	struct timeval tv;
	tv.tv_sec=200;
	tv.tv_usec=0;
	
	fd_set readfd;

	while(alive)
	{
		int ret=0;
		FD_ZERO(&readfd);
		FD_SET(rawsock,&readfd);
		ret=select(rawsock+1,&readfd,NULL,NULL,&tv);
		switch(ret)
		{
			case -1:
				break;
			case 0:
				break;
			default:
				{
					int fromlen=0;
					struct sockaddr from;
					
					int size=recv(rawsock,recv_buf,sizeof(recv_buf),0);
					if(errno==EINTR)
					{
						perror("recv()");
						continue;
					}

					ret=icmp_unpack(recv_buf,size);
					if(ret==-1)
					{
						continue;
					}
				}
				break;
		}
	}
}


static pingm_packet *icmp_findpacket(int seq)
{
	int i=0;
	pingm_packet *found=NULL;

	if(seq==-1)
	{
		for(i=0;i<128;i++)
		{
			if(pingpacket[i].flag==0)
			{
				found=&pingpacket[i];
				break;
			}
		}
	}
	else if(seq>=0)
	{
		for(i=0;i<128;i++)
		{
			if(pingpacket[i].seq==seq)
			{
				found=&pingpacket[i];
				break;
			}
		}
	}
	return found;
}

static void icmp_pack(struct icmp *icmph,int seq,struct timeval *tv,int length)
{
	unsigned char i=0;
	icmph->icmp_type=ICMP_ECHO;   //8
	icmph->icmp_code=0;
	icmph->icmp_cksum=0;
	icmph->icmp_seq=seq;
	icmph->icmp_id=pid;

	for(i=0;i<length;i++)
	{
		icmph->icmp_data[i]=i;
	}
	icmph->icmp_cksum=icmp_cksum((unsigned char*)icmph,length);
}


static unsigned short icmp_cksum(unsigned char *data,int len)
{
	int sum=0;
	int odd=len&0x01;     //jishu

	while(len&0xfffe)
	{
		sum+=*(unsigned short*)data;
		data+=2;
		len-=2;
	}

	if(odd)
	{
		unsigned short tmp=((*data)<<8)&0xff00;
		sum+=tmp;
	}

	sum=(sum>>16)+(sum&0xffff);
	sum+=(sum>>16);

	return ~sum;
}

static int icmp_unpack(char *buf,int len)
{
	int i,iphdrlen;
	struct ip *ip=NULL;
	struct icmp *icmp=NULL;
	int rtt;

	ip=(struct ip*)buf;
	iphdrlen=ip->ip_hl*4; //32bite
	icmp=(struct icmp*)(buf+iphdrlen);

	len-=iphdrlen;

	if(len<8)
	{
		printf("ICMP packet\'s length is less than 8\n");
		return -1;
	}

	if((icmp->icmp_type==ICMP_ECHOREPLY) && (icmp->icmp_id==pid))
	{
		struct timeval tv_internel,tv_recv,tv_send;

		pingm_packet *packet=icmp_findpacket(icmp->icmp_seq);

		if(packet==NULL)
		{
			return -1;
		}

		packet->flag=0;
		tv_send=packet->tv_begin;

		gettimeofday(&tv_recv,NULL);
		tv_internel=icmp_tvsub(tv_recv,tv_send);

		rtt=tv_internel.tv_sec*1000+tv_internel.tv_usec/1000;


		printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%d ms\n",len,
																 inet_ntoa(ip->ip_src),
																 icmp->icmp_seq,
																 ip->ip_ttl,
																 rtt);
		packet_recv++;
	}
	else
	{
		return -1;
	}
}


int main(int argc,char *argv[])
{
	//printf("aaaaaaaaaaaaaaaa\n");
	//printf("%d\n",__LINE__);
	int size=64*K;
	unsigned long inaddr=1;
	struct hostent *host=NULL;
	if(argc!=2)
	{
		icmp_usage();
		return -1;
	}
	//TT;


	memcpy(dest_str,argv[1],strlen(argv[1])+1);
	memset(pingpacket,0,sizeof(pingm_packet)*128);

	rawsock=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
	if(rawsock<0)
	{
		perror("socket()");
		return -2;
	}
	
	//TT;

	pid=getuid();

	setsockopt(rawsock,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size));
	bzero(&dest,sizeof(dest));
	dest.sin_family=AF_INET;
	

	//printf("dddddddddddddddddddddddd\n");


	inaddr=inet_addr(argv[1]);
	if(inaddr==INADDR_NONE)
	{
		host=gethostbyname(argv[1]);
		if(host==NULL)
		{
			perror("gethostbyname()");
			return -3;
		}
		memcpy((char*)&dest.sin_addr,host->h_addr,host->h_length);
	}
	else
	{
		memcpy((char*)&dest.sin_addr,&inaddr,sizeof(inaddr));
	}

	//printf("fffffffffffffffffffffffff\n");


	inaddr=dest.sin_addr.s_addr;
	//printf("ggggggggggggggggggggggg\n");
	//printf("%s\n",dest);
	printf("PING %s(%d.%d.%d.%d) 56 bytes of data.\n",dest_str,(inaddr&0x000000FF)>>0,
							       (inaddr&0x0000FF00)>>8,
							       (inaddr&0x00FF0000)>>16,
                                                             (inaddr&0xFF000000)>>24);
	

	//printf("hhhhhhhhhhhhhhhhhhhh\n");
	signal(SIGINT,icmp_sigint);

	alive=1;
	pthread_t send_id,recv_id;
	int err=0;

	err=pthread_create(&send_id,NULL,icmp_send,NULL);
	if(err<0)
	{
		perror("pthread_create()");
		return -4;
	}

	err=pthread_create(&recv_id,NULL,icmp_recv,NULL);
	if(err<0)
	{
		perror("pthread_create()");
		return -5;
	}

	pthread_join(send_id,NULL);
	pthread_join(recv_id,NULL);

	close(rawsock);
	return 0;

	return 0;
}
