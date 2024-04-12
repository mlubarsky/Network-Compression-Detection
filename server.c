#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <json-c/json.h>
#include <time.h>

#define BUFFER_SIZE 1024
#define THRESHOLD 100

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

	// Parse each config file field
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

/*
	Pre-probing phase
*/
void receive_config(int client_sock, char *config_buffer) {
    ssize_t bytes_received = recv(client_sock, config_buffer, BUFFER_SIZE, 0);
    if (bytes_received < 0) {
        perror("TCP receive failed");
        exit(EXIT_FAILURE);
    }
    config_buffer[bytes_received] = '\0';
}

/*
	Post-probing phase
*/
void send_detection_message(const char* message, struct config *config) {
	int client_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (client_sock < 0) {
		perror("TCP socket creation error");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in client_addr;
	memset(&client_addr, 0, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(config->tcp_post_probing_phase_port);

	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(config->tcp_post_probing_phase_port);

	int reuseaddr = 1;
	if (setsockopt(client_sock, SOL_SOCKET, SO_REUSEPORT, &reuseaddr, sizeof(reuseaddr)) < 0){
		perror("Invalid address");
		exit(EXIT_FAILURE);
	}

	if (bind(client_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("Bind failed");
		exit(EXIT_FAILURE);
	}

	// Listen for connections
    if (listen(client_sock, 3) < 0) {
        perror("TCP listen failed");
        exit(EXIT_FAILURE);
    }

    // Accept connection
    int server_sock;
    socklen_t addrlen = sizeof(client_addr);
    if ((server_sock = accept(client_sock, (struct sockaddr *)&client_addr, &addrlen)) < 0) {
        perror("TCP accept failed");
        exit(EXIT_FAILURE);
    }
	
    ssize_t bytes_sent = send(server_sock, message, strlen(message), 0);
    if (bytes_sent < 0) {
        perror("TCP send failed");
        exit(EXIT_FAILURE);
    }
}

/*
	Probing phase
	
*/
void receive_udp_packets(int udp_sock, struct config *config) {
    struct sockaddr_in client_address;
    socklen_t len = sizeof(client_address);
    
    int UDPbuffer[(config->udp_payload_size) + 2];
    clock_t start_time_low, start_time_high, end_time_low, end_time_high;
    double low_entropy_time, high_entropy_time;
    int i, packet_id;

    // Receive low entropy data
    printf("Receiving low entropy\n");
    start_time_low = clock();
    for (i = 0; i < config->number_of_udp_packets; i++) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(udp_sock, &fds);

        struct timeval timeout;
        timeout.tv_sec = 3; // 3-second timeout
        timeout.tv_usec = 0;

        int ready = select(udp_sock + 1, &fds, NULL, NULL, &timeout);
        if (ready == -1) {
            perror("select");
            exit(EXIT_FAILURE);
        } else if (ready == 0) { // Exit loop if no more packets received
            break;
        }

        recvfrom(udp_sock, UDPbuffer, config->udp_payload_size, 0, (struct sockaddr *) &client_address, &len);
        packet_id = ntohs(*(uint16_t*)UDPbuffer);
    }
    end_time_low = clock();
    low_entropy_time = ((((double)end_time_low) - ((double)start_time_low)) / ((double)CLOCKS_PER_SEC)) * 1000;
    printf("Low Entropy Time: %f\n", low_entropy_time);

    double remaining_time = config->inter_measurement_time - (low_entropy_time / 1000);
    if (remaining_time > 0) {
        printf("Sleeping for %f seconds...\n", remaining_time);
        usleep(remaining_time * 1000000);
    }

    // Receive high entropy data
    printf("Receiving high entropy\n");
    start_time_high = clock();
    for (i = 0; i < config->number_of_udp_packets; i++) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(udp_sock, &fds);

        struct timeval timeout;
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;

        int ready = select(udp_sock + 1, &fds, NULL, NULL, &timeout);
        if (ready == -1) {
            perror("select");
            exit(EXIT_FAILURE);
        } else if (ready == 0) { // Exit loop if no more packets received
            break;
        }

        recvfrom(udp_sock, UDPbuffer, config->udp_payload_size, 0, (struct sockaddr *) &client_address, &len);
        packet_id = ntohs(*(uint16_t*)UDPbuffer);
    }
    end_time_high = clock();
    high_entropy_time = ((((double)end_time_high) - ((double)start_time_high)) / ((double)CLOCKS_PER_SEC)) * 1000;
    printf("High Entropy Time: %f\n", high_entropy_time);

    // Calculate compression
    if ((high_entropy_time - low_entropy_time) > THRESHOLD) {
        printf("Compression detected!\n");
        send_detection_message("Compression detected!", config);
    } else {
        printf("No compression detected!\n");
        send_detection_message("No compression detected!", config);
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <Port>\n", argv[0]);
        return -1;
    }

    struct config config;
    char config_buffer[BUFFER_SIZE];

    // Create TCP socket for pre-probing phase
    int tcp_server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_server_sock < 0) {
        perror("TCP socket creation error");
        exit(EXIT_FAILURE);
    }

    // Set socket option to reuse address
    int opt = 1;
    if (setsockopt(tcp_server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Set up server and client address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(atoi(argv[1]));

    // Bind socket to port
    if (bind(tcp_server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("TCP bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(tcp_server_sock, 3) < 0) {
        perror("TCP listen failed");
        exit(EXIT_FAILURE);
    }

    // Accept connection
    int tcp_client_sock;
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);
    if ((tcp_client_sock = accept(tcp_server_sock, (struct sockaddr *)&client_addr, &addrlen)) < 0) {
        perror("TCP accept failed");
        exit(EXIT_FAILURE);
    }

    receive_config(tcp_client_sock, config_buffer);
    parse_config(config_buffer, &config);
    
    close(tcp_client_sock);
    close(tcp_server_sock);

    // Create UDP socket
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("UDP socket creation error");
        exit(EXIT_FAILURE);
    }

    // Set up UDP server address
    struct sockaddr_in udp_server_addr;
    memset(&udp_server_addr, 0, sizeof(udp_server_addr));
    udp_server_addr.sin_family = AF_INET;
    udp_server_addr.sin_addr.s_addr = INADDR_ANY;
    udp_server_addr.sin_port = htons(config.udp_destination_port);

    // Bind UDP socket to port
    if (bind(udp_sock, (struct sockaddr *)&udp_server_addr, sizeof(udp_server_addr)) < 0) {
        perror("UDP bind failed");
        exit(EXIT_FAILURE);
    }

    //Receive UDP packets
    receive_udp_packets(udp_sock, &config);
    close(udp_sock);

    return 0;
}
