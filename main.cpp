#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string>
#include <libnetfilter_queue/libnetfilter_queue.h>

char* compare;

typedef struct IPHeader{
    unsigned char IHL : 4; //  Header Length(4 bits), IP 헤더의 길이를 알 수 있는 필드값 * 4 하면 헤더 길이가 나옴. 일반적으로는 20이지만, 고정은 아니라고 함.
    unsigned char Version : 4; // IPv4 or IPv6(4 bits) 버전 확인 와 이게 뭔지 몰랐는데 검색해보니 비트 필드라는 것이다. Nibble 단위를 써본 적이 없으니.. 대신, struct에서만 사용 가능한듯?
    unsigned char TOS; // 서비스 우선 순위라고 하는데 구조상 1 byte
    unsigned short TotalLen; // IP부터 패킷의 끝의 총 길이(2 bytes)
    unsigned short ID; // 분열이 발생 했을 때 원래 데이터를 식별하기 위해서 사용
    unsigned char FO1 : 5; // 저장된 원래 데이터의 바이트 범위를 나타soa, dkvdml 3 bits
    unsigned char Flagsx : 1; // 항상 0,
    unsigned char FlagsD : 1; // 0: 분열 가능, 1: 분열 방지
    unsigned char FlagsM : 1; // 0: 마지막 조각, 1: 조각 더 있음.
    unsigned char FO2; // enldml 8 bits
    unsigned char TTL; // 패킷이 너무 오래 있어서 버려야 하는지 여부, 이동 할때마다 -1 한다고 함. 테스트 해보자
    unsigned char Protocol; // 프로토콜 ^^
    unsigned short HeaderCheck; // ip header checksum.
    struct in_addr SrcAdd;
    struct in_addr DstAdd;
}IPH;

typedef struct TCPHeader{
    unsigned short SrcPort;
    unsigned short DstPort;
    unsigned int SN; // 순서 맞추기 용 시퀀스 넘버
    unsigned int AN; // 수신 준비 완료와 수신 완료 되었다는 메세지를 전달함.
    unsigned char Reserved : 4; // 예약 영역, 안쓰이는 건가?
    unsigned char Offset : 4; // 앞의 헤더의 길이를 나타냄
    unsigned char FlagsP : 1; // 데이터 포함 플래그
    unsigned char FlagsR : 1; // 수신 거부할 때 사용하는 플래그
    unsigned char FlagsS : 1; // 확인 메세지 전송 플래그
    unsigned char FlagsF : 1; // 연결 종료할 때 사용 플래그
    unsigned char FlagsC : 1; // 혼잡 윈도우 크기 감소 플래그?
    unsigned char FlagsE : 1; // 혼잡을 알리는 플래그
    unsigned char FlagsU : 1; // 필드가 가르키는 세그먼트 번호까지 긴급 데이터를 포함한다는 것을 알림(0이면 무시)
    unsigned char FlagsA : 1; // 확인 응답 메세지 플래그
    unsigned short Window; // 송신 시스템의 가용 수신 버퍼의 크기를 바이트 단위로 나타낸 것.
    unsigned short Check; // 체크섬.
    unsigned short UP; // Urgent Pointer인데, 이거는 CTF에서 뭐 숨길때나 봤지.. 실제로도 쓰이나..?
    //unsigned int Option[5]; // TCP Option 0~40 bytes.
}TCPH;

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0){}
            //printf("\n");
        //printf("%02x ", buf[i]);
    }
}

bool isHostInBlackList(struct nfq_data *tb)
{
    unsigned char *buf;
    int ret = nfq_get_payload(tb, &buf);

    IPH* iphdr = (IPH *)buf;
    int iphsize = iphdr->IHL * 4;
    TCPH* tcphdr = (TCPH*)(buf + iphsize);
    int tcphsize = tcphdr->Offset;
    buf += iphsize + tcphsize;

    if(tcphdr->DstPort != htons(80))
        return false;

    for(int i = 0; i < ret - 5; i++)
    {
        if (buf[i] == 0x48 && buf[i + 1] == 0x6f && buf[i + 2] == 0x73 && buf[i + 3] == 0x74 && buf[i + 4] == 0x3a && buf[i + 5] == 0x20)
        {
            int index = 0, length = 0;;
            for(index = i; index < ret - 1; index++)
            {
                if(buf[index] == 0x0d && buf[index + 1] == 0x0a)
                    break;
            }
            length = index - (i + 6);
            
            for(int j = 0; j < length; j++)
            {
                if(compare[j] == buf[i+6+j])
                    continue;
                else
                    return false;
            }
            return true;
        }
    }

    return false;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
    {
        printf("payload_len=%d ", ret);
        dump(data, ret);
    }
    fputc('\n', stdout);

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");
    bool test = isHostInBlackList(nfa);
    if(test == true)
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    else
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    if(argc != 2)
        return printf("[!] Usage : %s <host>\n", argv[0]");
    
    compare = argv[1]; 
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

