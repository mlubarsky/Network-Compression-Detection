#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <json-c/json.h>

#define BUFFER_SIZE 1024

// Store config file contents
struct Config {
    char Server_IP_Address[16];
    int UDP_Source_Port;
    int UDP_Destination_Port;
    int TCP_Head_SYN_Port;
    int TCP_Tail_SYN_Port;
    int TCP_Pre_Probing_Phase_Port;
    int TCP_Post_Probing_Phase_Port;
    int UDP_Payload_Size;
    int Inter_Measurement_Time;
    int Number_of_UDP_Packets;
    int TTL_for_UDP_Packets;
};

void parse_config(const char *config_json, struct Config *config) {
    struct json_object *config_obj = json_tokener_parse(config_json);
    if (!config_obj) {
        perror("Failed to parse JSON config");
        exit(EXIT_FAILURE);
    }

    // Extract values from JSON object and store in config struct
    strcpy(config->Server_IP_Address, json_object_get_string(json_object_object_get(config_obj, "Server_IP_Address")));
    config->UDP_Source_Port = json_object_get_int(json_object_object_get(config_obj, "UDP_Source_Port"));
    config->UDP_Destination_Port = json_object_get_int(json_object_object_get(config_obj, "UDP_Destination_Port"));
    config->TCP_Head_SYN_Port = json_object_get_int(json_object_object_get(config_obj, "TCP_Head_SYN_Port"));
    config->TCP_Tail_SYN_Port = json_object_get_int(json_object_object_get(config_obj, "TCP_Tail_SYN_Port"));
    config->TCP_Pre_Probing_Phase_Port = json_object_get_int(json_object_object_get(config_obj, "TCP_Pre_Probing_Phase_Port"));
    config->TCP_Post_Probing_Phase_Port = json_object_get_int(json_object_object_get(config_obj, "TCP_Post_Probing_Phase_Port"));
    config->UDP_Payload_Size = json_object_get_int(json_object_object_get(config_obj, "UDP_Payload_Size"));
    config->Inter_Measurement_Time = json_object_get_int(json_object_object_get(config_obj, "Inter_Measurement_Time"));
    config->Number_of_UDP_Packets = json_object_get_int(json_object_object_get(config_obj, "Number_of_UDP_Packets"));
    config->TTL_for_UDP_Packets = json_object_get_int(json_object_object_get(config_obj, "TTL_for_UDP_Packets"));

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

void receive_udp_packets(int udp_sock, struct Config *config) {
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char payload[config->UDP_Payload_Size];
    int packets_received = 0;

    // Receive UDP packets
    while (packets_received < config->Number_of_UDP_Packets * 2) {
        ssize_t bytes_received = recvfrom(udp_sock, payload, sizeof(payload), 0, (struct sockaddr *)&client_addr, &client_addr_len);
        if (bytes_received < 0) {
            perror("UDP receive failed");
            exit(EXIT_FAILURE);
        }
        //printf("Received UDP packet %d\n", packets_received + 1);
        packets_received++;
    }
}

int main(int argc, char** argv) {
	if (argc < 2) {
		printf("Usage: %s <Port>\n", argv[0]);
		return -1;
	}
    struct Config config;
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

    // printf("Server IP Address: %s\n", config.Server_IP_Address);
    // printf("UDP Source Port: %d\n", config.UDP_Source_Port);
    // printf("UDP Destination Port: %d\n", config.UDP_Destination_Port);
    // printf("TCP Head SYN Port: %d\n", config.TCP_Head_SYN_Port);
    // printf("TCP Tail SYN Port: %d\n", config.TCP_Tail_SYN_Port);
    // printf("TCP Pre-Probing Phase Port: %d\n", config.TCP_Pre_Probing_Phase_Port);
    // printf("TCP Post-Probing Phase Port: %d\n", config.TCP_Post_Probing_Phase_Port);
    // printf("UDP Payload Size: %d\n", config.UDP_Payload_Size);
    // printf("Inter-Measurement Time: %d\n", config.Inter_Measurement_Time);
    // printf("Number of UDP Packets: %d\n", config.Number_of_UDP_Packets);
    // printf("TTL for UDP Packets: %d\n", config.TTL_for_UDP_Packets);

    // Create UDP socket
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("UDP socket creation error");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(config.UDP_Destination_Port);

    // Bind socket to port
    if (bind(udp_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("UDP bind failed");
        exit(EXIT_FAILURE);
    }

    receive_udp_packets(udp_sock, &config);

    // Close sockets
    close(client_socket);
    close(server_fd);
    close(udp_sock);
    return 0;
}