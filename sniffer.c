#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>

/* ───────────────── 헤더 구조체 ───────────────── */

struct ethheader {
    u_char  ether_dhost[6];   /* 목적지 MAC */
    u_char  ether_shost[6];   /* 출발지 MAC */
    u_short ether_type;       /* 프로토콜 타입 */
};

struct ipheader {
    unsigned char      iph_ihl:4,   /* IP 헤더 길이 (4바이트 단위) */
                       iph_ver:4;   /* IP 버전 */
    unsigned char      iph_tos;
    unsigned short int iph_len;     /* 전체 IP 패킷 길이 */
    unsigned short int iph_ident;
    unsigned short int iph_flag:3,
                       iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol; /* 상위 프로토콜 (6=TCP) */
    unsigned short int iph_chksum;
    struct in_addr     iph_sourceip;
    struct in_addr     iph_destip;
};

struct tcpheader {
    u_short tcp_sport;        /* 출발지 포트 */
    u_short tcp_dport;        /* 목적지 포트 */
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;        /* 상위 4비트: TCP 헤더 길이 (4바이트 단위) */
#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

/* ───────────────── 콜백 함수 ───────────────── */

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    /* ── 1. Ethernet Header ── */
    struct ethheader *eth = (struct ethheader *)packet;

    /* TCP(IP) 패킷만 처리 */
    if (ntohs(eth->ether_type) != 0x0800) return;

    printf("=================================================\n");

    /* MAC 주소 출력 */
    printf("[Ethernet Header]\n");
    printf("  Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
        eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("  Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
        eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    /* ── 2. IP Header ── */
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    /* TCP 패킷만 처리 */
    if (ip->iph_protocol != IPPROTO_TCP) return;

    int ip_header_len = ip->iph_ihl * 4;   /* iph_ihl: 4바이트 단위 */

    printf("[IP Header]\n");
    printf("  Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("  Dst IP  : %s\n", inet_ntoa(ip->iph_destip));

    /* ── 3. TCP Header ── */
    struct tcpheader *tcp = (struct tcpheader *)(packet
                            + sizeof(struct ethheader)
                            + ip_header_len);

    int tcp_header_len = TH_OFF(tcp) * 4;  /* tcp_offx2 상위 4비트: 4바이트 단위 */

    printf("[TCP Header]\n");
    printf("  Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("  Dst Port: %d\n", ntohs(tcp->tcp_dport));

    /* ── 4. HTTP Payload ── */
    /*
     * IP 전체 길이 - IP 헤더 길이 - TCP 헤더 길이 = 페이로드 길이
     * iph_len은 이더넷 헤더를 제외한 IP 패킷 전체 길이
     */
    int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

    if (payload_len > 0) {
        u_char *payload = (u_char *)(packet
                          + sizeof(struct ethheader)
                          + ip_header_len
                          + tcp_header_len);

        printf("[HTTP Message] (payload: %d bytes)\n", payload_len);

        /* 출력 가능한 ASCII 문자만 출력 */
        for (int i = 0; i < payload_len; i++) {
            u_char c = payload[i];
            if (c >= 0x20 && c < 0x7f) {
                putchar(c);
            } else if (c == '\r') {
                /* skip \r */
            } else if (c == '\n') {
                putchar('\n');
            } else {
                putchar('.');
            }
        }
        putchar('\n');
    }

    printf("=================================================\n\n");
}

/* ───────────────── main ───────────────── */

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";   /* TCP만 캡처 */
    bpf_u_int32 net = 0;

    /* Step 1: NIC 열기 (인터페이스 이름은 환경에 따라 변경) */
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live 실패: %s\n", errbuf);
        return 1;
    }

    /* Step 2: 필터 컴파일 */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "pcap_compile 실패: %s\n", pcap_geterr(handle));
        return 1;
    }

    /* Step 3: 필터 적용 */
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    printf("TCP 패킷 캡처 시작... (Ctrl+C로 종료)\n\n");

    /* Step 4: 무한 루프로 패킷 캡처 */
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
