# TCP Packet Sniffer

C 언어와 libpcap 라이브러리를 활용한 네트워크 패킷 분석 프로그램이다.  
네트워크 인터페이스를 통해 TCP 패킷을 실시간으로 캡처하고, 각 계층의 헤더 정보와 HTTP 메시지를 출력한다.

---

## 출력 정보

| 계층 | 출력 항목 |
|------|-----------|
| Ethernet | 출발지 MAC / 목적지 MAC |
| IP | 출발지 IP / 목적지 IP |
| TCP | 출발지 포트 / 목적지 포트 |
| Application | HTTP Message (페이로드) |

---

## 개발 환경

- **OS**: Ubuntu (VMware)
- **Language**: C
- **Library**: libpcap
- **NIC**: ens33

---

## 설치 및 빌드

### 1. libpcap 설치

```bash
sudo apt-get update
sudo apt-get install libpcap-dev
```

### 2. 컴파일

```bash
gcc -o sniffer sniffer.c -lpcap
```

### 3. 실행

```bash
sudo ./sniffer
```

> 패킷 캡처는 루트 권한이 필요하다.

---

## 테스트 방법

터미널을 두 개 열어서 진행한다.

**터미널 1** — 스니퍼 실행
```bash
sudo ./sniffer
```

**터미널 2** — HTTP 트래픽 발생
```bash
curl http://example.com
```

> HTTPS(포트 443)는 암호화되어 있어 HTTP 메시지가 보이지 않는다.  
> 반드시 **HTTP(포트 80)** 사이트로 테스트해야 한다.

---

## 출력 예시

```
TCP 패킷 캡처 시작... (Ctrl+C로 종료)

=================================================
[Ethernet Header]
  Src MAC : 00:0c:29:ab:cd:ef
  Dst MAC : 52:54:00:12:34:56
[IP Header]
  Src IP  : 192.168.244.128
  Dst IP  : 93.184.216.34
[TCP Header]
  Src Port: 54321
  Dst Port: 80
[HTTP Message] (payload: 87 bytes)
GET / HTTP/1.1
Host: example.com
User-Agent: curl/7.81.0
Accept: */*

=================================================
```

---

## 동작 원리

네트워크 패킷은 메모리 상에서 아래와 같이 연속된 바이트 배열로 구성된다.

```
[Ethernet Header] [  IP Header  ] [ TCP Header ] [ HTTP Data ]
     14 bytes       iph_ihl × 4   TH_OFF() × 4     나머지
```

각 헤더의 시작 위치는 이전 헤더의 크기만큼 포인터를 이동시켜 계산한다.

```c
// IP 헤더: 이더넷 헤더(고정 14바이트) 다음
struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
int ip_header_len = ip->iph_ihl * 4;

// TCP 헤더: 이더넷 + IP 헤더 다음
struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
int tcp_header_len = TH_OFF(tcp) * 4;

// HTTP 페이로드: 모든 헤더 다음
u_char *payload = (u_char *)(packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len);
int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;
```

### 핵심 포인트

- `iph_ihl` — 4바이트 단위의 IP 헤더 길이 → `× 4` 해야 실제 바이트
- `TH_OFF()` — tcp_offx2 필드의 상위 4비트 추출 → `× 4` 해야 실제 바이트
- `ntohs()` — 네트워크 바이트 순서(빅엔디안) → 호스트 바이트 순서 변환
- `iph_len` — 이더넷 헤더를 제외한 IP 패킷 전체 길이

---

## 파일 구조

```
.
├── sniffer.c       # 메인 소스 코드
└── README.md       # 프로젝트 설명
```

---

## 주의사항

- 실행 시 반드시 `sudo` 사용 (root 권한 필요)
- 인터페이스 이름은 환경에 따라 다름 (`ip a` 명령으로 확인)
- HTTP 평문 트래픽만 페이로드 확인 가능 (HTTPS 불가)
- 교육 및 학습 목적으로만 사용할 것

---

## 참고

- [libpcap 공식 문서](https://www.tcpdump.org/manpages/pcap.3pcap.html)
- [Ethernet Frame 구조](https://en.wikipedia.org/wiki/Ethernet_frame)
- [TCP/IP 헤더 구조](https://en.wikipedia.org/wiki/Internet_protocol_suite)
