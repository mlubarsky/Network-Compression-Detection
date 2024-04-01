#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>

#define BUFFER_SIZE 1024

#define PACKET_LEN 4096
#define SRC_PORT_X 12345         // Source port X
#define SRC_PORT_Y 12346         // Source port Y
#define DEST_PORT_X 50000        // Destination port X (inactive or closed)
#define DEST_PORT_Y 50001        // Destination port Y (inactive or closed)

struct config {
    char server_ip_address[16];
    int udp_source_port;
    int udp_destination_port;
    int tcp_head_syn_port;
    int tcp_tail_syn_port;
    int tcp_pre_probing_phase_port;
    int tcp_post_probing_phase_port;
    int udp_payload_size;
    int inter_measurement_time;
    int number_of_udp_packets;
    int ttl_for_udp_packets;
};

void parse_config(const char *config_json, struct config *config) {
    struct json_object *config_obj = json_tokener_parse(config_json);
    if (!config_obj) {
        perror("Failed to parse JSON config");
        exit(EXIT_FAILURE);
    }

    strcpy(config->server_ip_address, json_object_get_string(json_object_object_get(config_obj, "Server_IP_Address")));
    config->udp_source_port = json_object_get_int(json_object_object_get(config_obj, "UDP_Source_Port"));
    config->udp_destination_port = json_object_get_int(json_object_object_get(config_obj, "UDP_Destination_Port"));
    config->tcp_head_syn_port = json_object_get_int(json_object_object_get(config_obj, "TCP_Head_SYN_Port"));
    config->tcp_tail_syn_port = json_object_get_int(json_object_object_get(config_obj, "TCP_Tail_SYN_Port"));
    config->tcp_pre_probing_phase_port = json_object_get_int(json_object_object_get(config_obj, "TCP_Pre_Probing_Phase_Port"));
    config->tcp_post_probing_phase_port = json_object_get_int(json_object_object_get(config_obj, "TCP_Post_Probing_Phase_Port"));
    config->udp_payload_size = json_object_get_int(json_object_object_get(config_obj, "UDP_Payload_Size"));
    config->inter_measurement_time = json_object_get_int(json_object_object_get(config_obj, "Inter_Measurement_Time"));
    config->number_of_udp_packets = json_object_get_int(json_object_object_get(config_obj, "Number_of_UDP_Packets"));
    config->ttl_for_udp_packets = json_object_get_int(json_object_object_get(config_obj, "TTL_for_UDP_Packets"));

    json_object_put(config_obj);
}

void read_config_file(const char *config_file, char *config_buffer) {
    FILE *file = fopen(config_file, "r");
    if (!file) {
        perror("Failed to open config file");
        exit(EXIT_FAILURE);
    }
    fread(config_buffer, 1, BUFFER_SIZE, file);
    fclose(file);
}

// Function to calculate checksum
unsigned short checksum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <config_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct config config;
    char config_buffer[BUFFER_SIZE];
    char *config_file = argv[1];
    if (config_file == NULL) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    read_config_file(config_file, config_buffer);
    parse_config(config_buffer, &config);

  int sockfd;
    struct sockaddr_in dest_addr;
    char packet[PACKET_LEN];
    struct timeval start_time, end_time;
    double time_diff;

    // Create raw socket
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Fill in the IP header
    struct iphdr *ip_header = (struct iphdr *) packet;
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip_header->id = htons(54321);
    ip_header->frag_off = 0;
    ip_header->ttl = 255;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;  // Checksum to be filled later
    ip_header->saddr = inet_addr("127.0.0.1");
    ip_header->daddr = inet_addr(config.server_ip_address);

    // Fill in the TCP header (SYN packet)
    struct tcphdr *tcp_header = (struct tcphdr *) (packet + sizeof(struct iphdr));
    tcp_header->source = htons(SRC_PORT_X); // Source port X
    tcp_header->dest = htons(DEST_PORT_X);  // Destination port X
    tcp_header->seq = 0;
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5;
    tcp_header->fin = 0;
    tcp_header->syn = 1;  // TCP SYN flag
    tcp_header->rst = 0;
    tcp_header->psh = 0;
    tcp_header->ack = 0;
    tcp_header->urg = 0;
    tcp_header->window = htons(5840);  // Maximum allowed window size
    tcp_header->check = 0;  // Checksum to be filled later
    tcp_header->urg_ptr = 0;

    // Fill in destination address structure
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = ip_header->daddr;

    // Send SYN packet to port X
    if (sendto(sockfd, packet, ntohs(ip_header->tot_len), 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    // Record start time
    gettimeofday(&start_time, NULL);

    // Change source port for the next SYN packet
    tcp_header->source = htons(SRC_PORT_Y); // Source port Y
    tcp_header->dest = htons(DEST_PORT_Y);  // Destination port Y

    // Send SYN packet to port Y
    if (sendto(sockfd, packet, ntohs(ip_header->tot_len), 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    // Receive RST packets
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);
    char recv_buffer[PACKET_LEN];
    int recv_len;
    gettimeofday(&end_time, NULL);
    while ((recv_len = recvfrom(sockfd, recv_buffer, PACKET_LEN, 0, (struct sockaddr *) &recv_addr, &addr_len)) > 0) {
        struct iphdr *recv_ip_header = (struct iphdr *) recv_buffer;
        struct tcphdr *recv_tcp_header = (struct tcphdr *) (recv_buffer + sizeof(struct iphdr));
        if (recv_ip_header->protocol == IPPROTO_TCP && recv_tcp_header->rst) {
            // Record time difference
            time_diff = end_time.tv_sec - start_time.tv_sec + (end_time.tv_usec - start_time.tv_usec) / 1000000.0;
            printf("RST packet received after %f seconds.\n", time_diff);
            break;
        }
    }

    if (recv_len <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        perror("recvfrom");
        exit(EXIT_FAILURE);
    }

    if (recv_len <= 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
        // Timeout or no RST packet received
        printf("Failed to detect due to insufficient information.\n");
    }

    close(sockfd);

    return 0;
}