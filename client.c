#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <json-c/json.h>

#define BUFFER_SIZE 1024

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

void read_config_file(const char *config_file, char *config_buffer) {
    FILE *file = fopen(config_file, "r");
    if (!file) {
        perror("Failed to open config file");
        exit(EXIT_FAILURE);
    }
    fread(config_buffer, 1, BUFFER_SIZE, file);
    fclose(file);
}

void send_config(int tcp_sock, const char *config_file) {
    FILE *file = fopen(config_file, "r");
    if (!file) {
        perror("Failed to open config file");
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (send(tcp_sock, buffer, bytes_read, 0) < 0) {
            perror("Failed to send config file");
            exit(EXIT_FAILURE);
        }
    }

    if (bytes_read < 0) {
        perror("Failed to read config file");
        exit(EXIT_FAILURE);
    }

    fclose(file);
    printf("Config file sent to server\n");
}

void send_udp_packets(int udp_sock, struct Config *config) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config->UDP_Destination_Port);
    server_addr.sin_addr.s_addr = inet_addr(config->Server_IP_Address);

    // Send low entropy UDP packets
    for (int i = 0; i < config->Number_of_UDP_Packets; i++) {
        char payload[config->UDP_Payload_Size];
        memset(payload, 0, sizeof(payload)); // Fill payload with zeros
        sendto(udp_sock, payload, sizeof(payload), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    }

    sleep(config->Inter_Measurement_Time); // Wait for 15 seconds
    
    // Send high entropy UDP packets
    char high_entropy[config->UDP_Payload_Size];
    FILE *urandom = fopen("/dev/urandom", "r");
    fread(high_entropy, 1, config->UDP_Payload_Size, urandom);
    fclose(urandom);
    for (int i = 0; i < config->Number_of_UDP_Packets; i++) {
        sendto(udp_sock, high_entropy, sizeof(high_entropy), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    }
    printf("Finished sending low and high entropy packets\n");
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <config_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

	// Config file reading and parsing
    struct Config config;
    char config_buffer[BUFFER_SIZE];
    char *config_file = argv[1];
    if (config_file == NULL) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    read_config_file(config_file, config_buffer);
    parse_config(config_buffer, &config);

	// Create TCP socket
    int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock < 0) {
        perror("TCP socket creation error");
        exit(EXIT_FAILURE);
    }
	
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config.UDP_Destination_Port);

    if (inet_pton(AF_INET, config.Server_IP_Address, &server_addr.sin_addr) <= 0) {
        perror("Invalid TCP address");
        exit(EXIT_FAILURE);
    }

    if (connect(tcp_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("TCP Connection Failed");
        exit(EXIT_FAILURE);
    }

	// Send config file to server
    send_config(tcp_sock, config_file);
    close(tcp_sock);

    // Create UDP socket
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("UDP socket creation error");
        exit(EXIT_FAILURE);
    }

    send_udp_packets(udp_sock, &config);
    close(udp_sock);
    return 0;
}
