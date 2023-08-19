#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

char *blocked_domain;

u_int32_t print_pkt(struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
    }
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");

    unsigned char *payload;
    int payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len >= 0) {
        printf("payload_len=%d\n", payload_len);
    }

    struct iphdr *ip_header = (struct iphdr *)payload;
    if (ip_header->protocol == 6) { // TCP
        struct tcphdr *tcp_header = (struct tcphdr *)(payload + (ip_header->ihl << 2));
        char *http_payload = (char *)(payload + (ip_header->ihl << 2) + (tcp_header->doff << 2));
        
        char host_string[256];
        snprintf(host_string, sizeof(host_string), "Host: %s", blocked_domain);
        
        if (strstr(http_payload, host_string) != NULL) {
            printf("Blocking packet\n");
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }
    }
    
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <blocked_domain>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    blocked_domain = argv[1];

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

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        printf("pkt received\n");
        nfq_handle_packet(h, buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);
    
    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

