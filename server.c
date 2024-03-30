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

    // Extract values from JSON object and store in config struct
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

void receive_config(int client_socket, char *config_buffer) {
    ssize_t bytes_received = recv(client_socket, config_buffer, BUFFER_SIZE, 0);
    if (bytes_received < 0) {
        perror("TCP receive failed");
        exit(EXIT_FAILURE);
    }
    config_buffer[bytes_received] = '\0';
}

void receive_udp_packets(int udp_sock, struct config *config) {
	struct sockaddr_in client_address;
	socklen_t len = sizeof(client_address);
	int UDPbuffer[(config->udp_payload_size)+2];
	clock_t start_time, end_time;
	double total_time, low_entropy_time, high_entropy_time;
	int i, packet_id;

	//Receive low entropy data
    printf("Receiving low entropy \n");
    memset(UDPbuffer, 0, sizeof(UDPbuffer));
    start_time = clock();
    for (i = 0; i < config->number_of_udp_packets; i++) {
        recvfrom(udp_sock, UDPbuffer, config->udp_payload_size + 2, 0, (struct sockaddr *) &client_address, &len);
        packet_id = (int)(((unsigned)UDPbuffer[0]) | ((unsigned)UDPbuffer[1] << 8));
        //packet_id = ntohs(*(uint16_t*)UDPbuffer);
        printf("Retrieved Low Entropy Packet Number: %d\n", packet_id);
    }
    end_time = clock();
    total_time  = (((double)end_time) - ((double)start_time)) / ((double)CLOCKS_PER_SEC);
    low_entropy_time = total_time * 1000;
    printf("Low Entropy Time: %f\n", low_entropy_time);


	start_time = 0, end_time = 0;


	//Receive high entropy data
	printf("Receiving high entropy..\n");
	memset(UDPbuffer, 0, sizeof(UDPbuffer));
	start_time = clock();
	memset(&UDPbuffer, 0, config->udp_payload_size + 2);
	for (i = 0; i < config->number_of_udp_packets; i++) {
	    recvfrom(udp_sock, UDPbuffer, config->udp_payload_size + 2, 0, (struct sockaddr *) &client_address, &len);
	    packet_id = ntohs(*(uint16_t*)UDPbuffer);
	    printf("Retrieved High Entropy Packet Number: %d\n", packet_id);
	}
    end_time = clock();
    total_time  = (((double)end_time) - ((double)start_time)) / ((double)CLOCKS_PER_SEC);
    high_entropy_time = total_time * 1000;
    printf("High Entropy Time: %f\n", high_entropy_time);


    //Calculate compression
    if ((high_entropy_time - low_entropy_time) > THRESHOLD) {
        printf("Compression detected!\n");
    } else {
        printf("No compression detected!\n");
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
	    printf("Usage: %s <Port>\n", argv[0]);
	    return -1;
    }
    
    struct config config;
    char config_buffer[BUFFER_SIZE];

    // Create TCP socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("TCP socket creation error");
        exit(EXIT_FAILURE);
    }

    // Set up server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(atoi(argv[1]));

    // Bind socket to port
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("TCP bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("TCP listen failed");
        exit(EXIT_FAILURE);
    }

    // Accept connection
    int client_socket;
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);
    if ((client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen)) < 0) {
        perror("TCP accept failed");
        exit(EXIT_FAILURE);
    }

    receive_config(client_socket, config_buffer);
    parse_config(config_buffer, &config);

    // Create UDP socket
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("UDP socket creation error");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(config.udp_destination_port);

    // Bind socket to port
    if (bind(udp_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("UDP bind failed");
        exit(EXIT_FAILURE);
    }

    receive_udp_packets(udp_sock, &config);

    close(client_socket);
    close(server_fd);
    close(udp_sock);
    return 0;
}