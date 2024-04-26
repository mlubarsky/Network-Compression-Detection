#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#define THRESHOLD 100
#define BUFFER_SIZE 1024
#define PACKET_LEN 4096

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

unsigned short tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    unsigned long sum = 0;
    unsigned short *ptr;
    int tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
    int i;

    // Pseudo-header checksum
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += iph->saddr & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += iph->daddr & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcplen);

    // TCP header checksum
    ptr = (unsigned short *)tcph;
    for (i = tcplen; i > 1; i -= 2)
        sum += *ptr++;
    if (i == 1)
        sum += *((unsigned char *)ptr);

    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (unsigned short)(~sum);
}

unsigned short ip_checksum(struct iphdr *iph) {
    unsigned long sum = 0;
    unsigned short *ptr;

    // IP header checksum
    ptr = (unsigned short *)iph;
    for (int i = iph->ihl * 2; i > 0; i--)
        sum += *ptr++;
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (unsigned short)(~sum);
}

void send_udp_packets_low(int udp_sock, struct config *config) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config->udp_destination_port);
    server_addr.sin_addr.s_addr = inet_addr(config->server_ip_address);

    struct sockaddr_in client_addr;
	memset(&client_addr, 0, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	client_addr.sin_port = htons(config->udp_source_port);

	int reuseaddr = 1;
	if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) < 0) {
		perror("Invalid address");
		exit(EXIT_FAILURE);
	}

	if (bind(udp_sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
		perror("Bind failed");
		exit(EXIT_FAILURE);
	}

    // Set the df flag in  IP header
    int DF = IP_PMTUDISC_DO;
    if (setsockopt(udp_sock, IPPROTO_IP, IP_MTU_DISCOVER, &DF, sizeof(DF)) < 0) {
        perror("Failed to set DF flag");
        exit(EXIT_FAILURE);
    }

	// Set the ttl value in IP header
    int ttl = config->ttl_for_udp_packets;
    if (setsockopt(udp_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
    	perror("Failed to set DF flag");
     	exit(EXIT_FAILURE);
    }

    //Send low entropy UDP packets
    for (int i = 0; i < config->number_of_udp_packets; i++) {
        char payload[config->udp_payload_size]; // Set payload size to be 1000
        *(uint16_t*)payload = htons(i);

        memset(payload + 2, 0, config->udp_payload_size - 2); // Fill payload with zeros
        sendto(udp_sock, payload, (config->udp_payload_size), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
        usleep(200);
    }
    printf("Low entropy UDP packets sent\n");
}

void send_udp_packets_high(int udp_sock, struct config *config) {
    char high_entropy[config->udp_payload_size];
    FILE *urandom = fopen("/dev/urandom", "r");
    if (!urandom) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }
    fread(high_entropy, 1, config->udp_payload_size, urandom);
    fclose(urandom);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config->udp_destination_port);
    server_addr.sin_addr.s_addr = inet_addr(config->server_ip_address);

    struct sockaddr_in client_addr;
	memset(&client_addr, 0, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	client_addr.sin_port = htons(config->udp_source_port);

	int reuseaddr = 1;
	if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) < 0) {
		perror("Invalid address");
		exit(EXIT_FAILURE);
	}

	if (bind(udp_sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
		perror("Bind failed");
		exit(EXIT_FAILURE);
	}

    // Set the df flag in IP header
    int DF = IP_PMTUDISC_DO;
    if (setsockopt(udp_sock, IPPROTO_IP, IP_MTU_DISCOVER, &DF, sizeof(DF)) < 0) {
        perror("Failed to set DF flag");
        exit(EXIT_FAILURE);
    }

	// Set the ttl in IP header
    int ttl = config->ttl_for_udp_packets;
    if (setsockopt(udp_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
    	perror("Failed to set DF flag");
     	exit(EXIT_FAILURE);
    }

    //Send high entropy UDP packets
    for (int i = 0; i < config->number_of_udp_packets; i++) {
        char payload[config->udp_payload_size]; // Set payload size to be 1000
        *(uint16_t*)payload = htons(i);

        memcpy(payload + 2, high_entropy, config->udp_payload_size - 2); // Copy high entropy data to payload
        sendto(udp_sock, payload, (config->udp_payload_size), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
        usleep(200);
    }
    printf("High entropy UDP packets sent\n");
}

void *send_packets(void *arg) {
    struct config *config = (struct config *)arg;

    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Fill in IP header and TCP header for SYN head packet
    struct sockaddr_in dest_addr;
    char packet[PACKET_LEN];
    struct iphdr *ip_header = (struct iphdr *)packet;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));
    
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip_header->id = 0;
    ip_header->frag_off = 0;
    ip_header->ttl = 255;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;
    ip_header->saddr = inet_addr("169.254.200.14"); // Hard-coded client IP
    ip_header->daddr = inet_addr(config->server_ip_address);
    
    tcp_header->source = htons(config->tcp_pre_probing_phase_port);
    tcp_header->dest = htons(config->tcp_head_syn_port);
    tcp_header->seq = 0;
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5;
    tcp_header->fin = 0;
    tcp_header->syn = 1;
    tcp_header->rst = 0;
    tcp_header->psh = 0;
    tcp_header->ack = 0;
    tcp_header->urg = 0;
    tcp_header->window = htons(5840);
    tcp_header->check = 0;
    tcp_header->urg_ptr = 0;

    // Calculate TCP checksum
    tcp_header->check = tcp_checksum(ip_header, tcp_header);

    // Fill in destination address struct
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = ip_header->daddr;

    // Send SYN head packet for low entropy
    if (sendto(sockfd, packet, ntohs(ip_header->tot_len), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    // Set up UDP socket
    int udp_sock_low = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock_low < 0) {
        perror("UDP socket creation error");
        exit(EXIT_FAILURE);
    }

    // Send UDP packets
    sleep(1); // Sleep to catch the RST first before sending UDP packets
    send_udp_packets_low(udp_sock_low, config);

    // Fill in TCP header for SYN tail packet
    tcp_header->source = htons(config->tcp_pre_probing_phase_port);
    tcp_header->dest = htons(config->tcp_tail_syn_port);

    tcp_header->check = 0;
    tcp_header->check = tcp_checksum(ip_header, tcp_header);

    // Send SYN tail packet for low entropy
    if (sendto(sockfd, packet, ntohs(ip_header->tot_len), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    close(udp_sock_low);

	sleep(config->inter_measurement_time); // Wait for 15 seconds

	// Fill in TCP header for SYN tail packet
    tcp_header->source = htons(config->tcp_post_probing_phase_port);
    tcp_header->dest = htons(config->tcp_head_syn_port);

    tcp_header->check = 0;
    tcp_header->check = tcp_checksum(ip_header, tcp_header);

    // Send SYN head packet
    if (sendto(sockfd, packet, ntohs(ip_header->tot_len), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    // Set up UDP socket
    int udp_sock_high = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock_high < 0) {
        perror("UDP socket creation error");
        exit(EXIT_FAILURE);
    }
	// Send UDP packets
  	sleep(1); // Sleep to catch the RST first before sending UDP packets
   	send_udp_packets_high(udp_sock_high, config);

	// Fill in TCP header for SYN tail packet
    tcp_header->source = htons(config->tcp_post_probing_phase_port);
    tcp_header->dest = htons(config->tcp_tail_syn_port);

    tcp_header->check = 0;
    tcp_header->check = tcp_checksum(ip_header, tcp_header);

    // Send SYN tail packet
    if (sendto(sockfd, packet, ntohs(ip_header->tot_len), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    close(sockfd);
    close(udp_sock_high);

    return NULL;
}

void *receive_rst_packets(void *arg) {
	clock_t start_time_low, start_time_high, end_time_low, end_time_high;
    double low_entropy_time, high_entropy_time;
    
    int recvsock;
    if ((recvsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Receive RST for head packet for low entropy train
    char recv_buffer[PACKET_LEN];
    int recv_len;
    while (1) {
        recv_len = recvfrom(recvsock, recv_buffer, PACKET_LEN, 0, NULL, NULL);
        struct iphdr *recv_ip_header = (struct iphdr *)recv_buffer;
        struct tcphdr *recv_tcp_header = (struct tcphdr *)(recv_buffer + sizeof(struct iphdr));
        if (recv_ip_header->protocol == IPPROTO_TCP && recv_tcp_header->rst) {
        	start_time_low = clock();
            printf("Low entropy train: RST for Head packet received.\n");
            break;
        }
    }
    if (recv_len < 0) {
        perror("recvfrom");
        exit(EXIT_FAILURE);
    }
	// Receive RST for tail packet for low entropy train
    while (1) {
		recv_len = recvfrom(recvsock, recv_buffer, PACKET_LEN, 0, NULL, NULL);
		struct iphdr *recv_ip_header = (struct iphdr *)recv_buffer;
		struct tcphdr *recv_tcp_header = (struct tcphdr *)(recv_buffer + sizeof(struct iphdr));
		if (recv_ip_header->protocol == IPPROTO_TCP && recv_tcp_header->rst) {
			end_time_low = clock();
			printf("Low entropy train: RST for Tail packet received.\n");
			break;
		}
	}
	if (recv_len < 0) {
		perror("recvfrom");
		exit(EXIT_FAILURE);
	}
	low_entropy_time = ((((double)end_time_low) - ((double)start_time_low)) / ((double)CLOCKS_PER_SEC)) * 1000;
	printf("Low Entropy Time: %f\n", low_entropy_time);

	// Receive RST for head packet for high entropy train
    while (1) {
        recv_len = recvfrom(recvsock, recv_buffer, PACKET_LEN, 0, NULL, NULL);
        struct iphdr *recv_ip_header = (struct iphdr *)recv_buffer;
        struct tcphdr *recv_tcp_header = (struct tcphdr *)(recv_buffer + sizeof(struct iphdr));
        if (recv_ip_header->protocol == IPPROTO_TCP && recv_tcp_header->rst) {
        	start_time_high = clock();
            printf("High entropy train: RST for Head packet received.\n");
            break;
        }
    }
    if (recv_len < 0) {
        perror("recvfrom");
        exit(EXIT_FAILURE);
    }
	// Receive RST for tail packet for high entropy train
    while (1) {
		recv_len = recvfrom(recvsock, recv_buffer, PACKET_LEN, 0, NULL, NULL);
		struct iphdr *recv_ip_header = (struct iphdr *)recv_buffer;
		struct tcphdr *recv_tcp_header = (struct tcphdr *)(recv_buffer + sizeof(struct iphdr));
		if (recv_ip_header->protocol == IPPROTO_TCP && recv_tcp_header->rst) {
			end_time_high = clock();
			printf("High entropy train: RST for Tail packet received.\n");
			break;
		}
	}
	if (recv_len < 0) {
		perror("recvfrom");
		exit(EXIT_FAILURE);
	}
	high_entropy_time = ((((double)end_time_high) - ((double)start_time_high)) / ((double)CLOCKS_PER_SEC)) * 1000;
    printf("High Entropy Time: %f\n", high_entropy_time);

    // Calculate compression
    if ((high_entropy_time - low_entropy_time) > THRESHOLD) {
        printf("Compression detected!\n");
    } else {
        printf("No compression detected!\n");
    }

    close(recvsock);
    
    return NULL;
}

int main(int argc, char **argv) {
	if (argc != 2) {
	    printf("Usage: %s <config_file>\n", argv[0]);
	    exit(EXIT_FAILURE);
	}

    pthread_t send_thread, receive_thread;
    struct config config;
    char config_buffer[BUFFER_SIZE];
    char *config_file = argv[1];
    if (config_file == NULL) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    read_config_file(config_file, config_buffer);
    parse_config(config_buffer, &config);

    // Create send_packets thread
    if (pthread_create(&send_thread, NULL, send_packets, &config) != 0) {
        perror("pthread_create for send_packets");
        exit(EXIT_FAILURE);
    }

    // Create receive_rst_packets thread
    if (pthread_create(&receive_thread, NULL, receive_rst_packets, NULL) != 0) {
        perror("pthread_create for receive_rst_packets");
        exit(EXIT_FAILURE);
    }

    pthread_join(send_thread, NULL);
    pthread_join(receive_thread, NULL);
	
    return 0;
}
