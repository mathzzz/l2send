#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pcap.h>
//#include <linux/include/ip.h>
#include <netinet/ip.h> //struct iphdr
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>
#include <netinet/ether.h>

#define min(a, b ) ((a) > (b) ? (b):(a) )
#define log_error fprintf(stderr, "error:%s:%d:%s\r\n", __func__, __LINE__, strerror(errno))

struct ether_lldp {
    int type;
};

struct ether_lacp {
    int type;
};


typedef struct l2 {
    unsigned char dmac[6];
    unsigned char smac[6];
    unsigned short etype;
    unsigned char data[0];
}L2;

struct vlan {
    unsigned short tpid;
    unsigned short tci;
};

typedef union {
    struct ether_arp  *arp;
    struct ether_lldp *lldp;
    struct ether_lacp *lacp;
    struct iphdr      *ip;
    struct ip6_hdr    *ip6;
}L3;

typedef union {
    struct icmphdr   *icmp;
    struct icmp6_hdr *icmp6;
    struct tcphdr    *tcp;
    struct udphdr    *udp;
    struct igmp      *igmp;
}L4;


struct netpkt{
    struct netpkt *next;
    unsigned int etype;
    unsigned int protocol;
    size_t  pktlen;
    char *raw;
    unsigned char *offload; // l4 offload
    L2 *l2; // ether L2 is the same
    struct vlan *vlan;
    L3 l3;
    L4 l4;
    char data[0]; //raw packet data
};


#define TPL_ICMP 1
#define TPL_TCP  1
#define TPL_UDP  17

struct netpkt_tpl {
    struct netpkt *first;
    struct netpkt **last;

    struct netpkt *lldp;
    struct netpkt_*lacp;
    struct netpkt *arp;
    struct netpkt *icmp;
    struct netpkt *icmp6;
    struct netpkt *udp;
    struct netpkt *tcp;
    struct netpkt *igmp;
};

static pcap_t *handle;
static char errbuf[PCAP_ERRBUF_SIZE];
static unsigned char pktbuff[2048];



static inline
unsigned int xdigit(unsigned int a)
{
   unsigned int x;

    if(isdigit(a))
        x = a - '0';
    else
        x= 10+a-'a';
    return x;

}

static inline
int sncat(char *buf, size_t bufsize, ...)
{
    char *chip;
    size_t fill_len;
    size_t chip_len;
    va_list arg;

    va_start(arg, bufsize);

    for(fill_len=0; chip = va_arg(arg, char *); fill_len+=chip_len) {
        chip_len = strlen(chip);
        if(bufsize > fill_len + chip_len) {
            memcpy(buf+fill_len, chip, chip_len);
        } else {
            break;
        }
    }

    buf[fill_len] = 0;
    va_end(arg);

    return fill_len;
}


static inline
void *hex2bin(unsigned char *hex)
{
    static unsigned char buf[2048]; // "45000054ae3140004001b3e3ac100c0a0a161664"
    static int offset;
    char *pc = buf;
    int i;
    int len = strlen((char *)hex)/2;

    if(hex == NULL)
        offset = 0;

    pc += offset;

    len = min(len, sizeof(buf));
    for(i=0; i<len; i++)
    {
        pc[i] = xdigit(*hex++) *16 + xdigit(*hex++);
    }
    offset += len;

    return buf+offset-len;

}

static inline unsigned short csum(unsigned short *buf, int buflen)
{
    unsigned int sum;
    for(sum = 0; buflen > 0; buflen-=2)
        sum += *buf++;

    if(buflen > 0) // buflen is odd
        sum += *(unsigned char *)buf;

    while(sum >> 16)
        sum=(sum>>16)+(sum&0xFFFF);

    return ~sum;
}

static inline int do_l2send(char *pkt, int pktlen)
{
    int ret;
    int len;

    ret = pcap_sendpacket(handle, pkt, pktlen);
}

int l2send_conf(char *devname)
{
    handle = pcap_open_live(devname, 1500, 0, 1000, NULL /* errbuf */);
    if(handle == NULL)
        return -1;
    return 0;
}

int getdigit(FILE *file)
{

enum {
    STA_INIT,
    STA_DGT,
    STA_NEWLINE,
    STA_OTHER
};

    int ch=0;
    static int state = STA_INIT;
    while( EOF != (ch=fgetc(file))) {
        if((state != STA_OTHER) && (isxdigit(ch)||isdigit(ch))) {
            state = STA_DGT;
            return ch;
        } else if(ch == '\n') {
            if(state == STA_NEWLINE) {
                state = STA_INIT;
                return 0;
            }
            state = STA_NEWLINE;
        }else if(!isspace(ch)) { //other
            state = STA_OTHER;
        }
    }

    return ch;
}


struct netpkt *pkt_parse(unsigned char *raw, size_t pktlen, struct netpkt *pkt)
{
    int offset;
    pkt->next = NULL;

    memset(pkt, 0, sizeof(struct netpkt));
    memcpy(pkt->data, raw, pktlen);
    pkt->raw = (void *)pkt->data;
    pkt->pktlen = pktlen;

    offset = 0;
    pkt->l2 = (void *)pkt->raw+offset;
    offset += 12+2;

    // parse pkt
    pkt->etype = ntohs(pkt->l2->etype);

    if(pkt->etype == 0x8100) {
        offset+=4; //vlan
        pkt->etype = ntohs(*(unsigned short *)(pkt->raw+offset));
    }

    if(pkt->etype == 0x0800) {
        pkt->l3.ip = (void *)(pkt->raw+offset);
    }

    switch(pkt->etype) {
        case 0x0800:
            offset += 20;
            pkt->protocol = pkt->l3.ip->protocol;
            break;
        case 0x86dd:
            offset += 32;
            break;
        default:
            log_error;
            break;
    }

    switch(pkt->l3.ip->protocol) {
        case 1:
            pkt->l4.icmp = (void *)(pkt->raw+offset);
        case 2:
            pkt->l4.igmp = (void *)(pkt->raw+offset);
        case 17:
            pkt->l4.udp = (void *)(pkt->raw+offset);
            offset+=8;
            break;
        case 6:
            pkt->l4.tcp = (void *)(pkt->raw+offset);
            offset+=20;
            break;
        default:
            log_error;
            break;

    }
    pkt->offload = pkt->raw + offset;

    return pkt;

}

static struct netpkt *get_pkt_from_tpl(FILE *file)
{
    int c1, c2, i;
    char buf[2048];
    struct netpkt *pkt;


    // 跳过空行
    while(0 == (c1 = getdigit(file)))
        ; // 获取第一个digit
    if(isdigit(c1) || isxdigit(c1))
        ungetc(c1, file);
    else
        return NULL;

    for(i=0;i<sizeof(buf); i++) {
        c1 = getdigit(file);
        if(c1 == 0)
            break;
        c2 = getdigit(file);
        buf[i] = xdigit(c1)*16 + xdigit(c2);
    }

    pkt = malloc(sizeof(struct netpkt) + i);
    pkt_parse(buf, i, pkt) ;
    return pkt;
}

int load_pkt_template(const char *filename, struct netpkt_tpl *pkt_tpl)
{
#define skip_space(pc)  while(isspace(*pc))pc++;
    struct netpkt *pkt;
    FILE *file = fopen(filename, "r");

    if(file == NULL) {
        log_error;
        return -1;
    }

    pkt_tpl->first = get_pkt_from_tpl(file);
    pkt_tpl->last = &pkt_tpl->first->next;

    while(pkt = get_pkt_from_tpl(file)) {
        *pkt_tpl->last = pkt;
        pkt_tpl->last = &pkt->next;
    }

    // 挂载到模板
    struct netpkt *iter;
    for(iter=pkt_tpl->first; iter; iter=iter->next) {
        printf("protocol=%d\n", iter->protocol);
        if(iter->etype == 0x0800) {
            switch(iter->protocol) {
            case 1:
                pkt_tpl->icmp = iter;
                break;
            case 2:
                pkt_tpl->igmp = iter;
                break;
            case 6:
                pkt_tpl->tcp = iter;
                break;
            case 17:
                pkt_tpl->udp = iter;
                break;
            default:
                break;
            }
        }
    }
}

int update_ip_csum(unsigned char *ip_header)
{
    struct iphdr *iphdr = (void *)ip_header;
    int header_len = iphdr->ihl << 2; // 5*4
    iphdr->check = 0;
    unsigned short ip_csum = csum((unsigned short *)(void *)ip_header, header_len);
    iphdr->check = ip_csum; // 已经是网络序 ?
    return 0;
}

int main(int argc, char *argv[]) // lsend devname 1s tcp|udp|icmp
{
    unsigned int i;
    int ret;
    int delay;
    int unit = 1;
    struct netpkt_tpl pkt_tpl;
    char *pc = "0s";

    if(argv[2])
        pc = argv[2];

    delay = atoi(pc);

    while(isdigit(*pc))
        pc++;

    if(*pc == 's')
        unit = 1000*1000;
    else if(*pc == 'm')
        unit = 1000;

    delay = delay * unit;

    memset(&pkt_tpl, 0, sizeof(pkt_tpl));
    load_pkt_template("/home/zjw/.pkt.tpl", &pkt_tpl);
    pkt_tpl.icmp = pkt_tpl.first;

    ret = l2send_conf(argv[1]);
    if(ret != 0)
        return ret;

struct netpkt *pkt = pkt_tpl.icmp;
if(argv[3])  {
    if(0==strcmp("udp", argv[3]))
        pkt = pkt_tpl.udp;
    else if(0 == strcmp("tcp", argv[3]))
        pkt = pkt_tpl.tcp;
}

    unsigned char *m = (void *)&pkt->l2->smac[0];
    unsigned char *ipc = (void *)&pkt->l3.ip->saddr;

    unsigned int *mac2 = (void *)m + 2;
    unsigned int *ip = (void *)ipc;

    for(i=0; i<65535*256; i++) {
        *ip = htonl(ntohl(*ip)+1);
        *mac2 = htonl(ntohl(*mac2) + 2);
        update_ip_csum((void *)pkt->l3.ip);
        usleep(delay);
#if 1
        fprintf(stderr, "[%s]:smac=%02x:%02x:%02x:%02x:%02x:%02x, sip=%hhu.%hhu.%hhu.%-3hhu\r",
               argv[3] ?: "icmp",
               m[0], m[1], m[2], m[3], m[4], m[5],
               ipc[0], ipc[1], ipc[2], ipc[3]);
#endif
        ret = do_l2send(pkt->raw, pkt->pktlen);
    }

    return 0;
}

