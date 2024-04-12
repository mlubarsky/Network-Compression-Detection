#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <json-c/json.h>

#define BUFFER_SIZE 1024

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

/*
	Pre-probing phase
*/
void send_config_file(int tcp_sock, struct config *config, char* config_file) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config->tcp_pre_probing_phase_port);

	struct sockaddr_in client_addr;
	memset(&client_addr, 0, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	client_addr.sin_port = htons(config->tcp_pre_probing_phase_port);

	int reuseaddr = 1;
	if (setsockopt(tcp_sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) < 0) {
		perror("Invalid address");
		exit(EXIT_FAILURE);
	}
	
	if (bind(tcp_sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
		perror("Bind failed");
		exit(EXIT_FAILURE);
	}

    // Convert IP address
    if (inet_pton(AF_INET, config->server_ip_address, &server_addr.sin_addr) <= 0) {
        perror("Invalid TCP address");
        exit(EXIT_FAILURE);
    }
    
    if (connect(tcp_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("TCP Connection Failed");
        exit(EXIT_FAILURE);
    }

    FILE *file = fopen(config_file, "r");
    if (!file) {
        perror("Failed to open config file");
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

	// Send config file
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
}

/*
	Post-probing phase
	
*/
void receive_detection_message(int tcp_sock) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received = recv(tcp_sock, buffer, BUFFER_SIZE, 0);
    if (bytes_received < 0) {
        perror("TCP receive failed");
        exit(EXIT_FAILURE);
    }
    buffer[bytes_received] = '\0';
    printf("Compression Detection Message from Server: %s\n", buffer);
}

/*
    Probing Phase

*/
void send_udp_packets(int udp_sock, struct config *config) {
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

    // Set the df flag in the IP header
    int DF = IP_PMTUDISC_DO;
    if (setsockopt(udp_sock, IPPROTO_IP, IP_MTU_DISCOVER, &DF, sizeof(DF)) < 0) {
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

    sleep(config->inter_measurement_time); // Wait for 15 seconds

    //Send high entropy UDP packets
    for (int i = 0; i < config->number_of_udp_packets; i++) {
        char payload[config->udp_payload_size]; // Set payload size to be 1000
        *(uint16_t*)payload = htons(i);

        memcpy(payload + 2, high_entropy, config->udp_payload_size - 2); // Copy high entropy data to payload
        sendto(udp_sock, payload, (config->udp_payload_size), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
        usleep(200);
    }
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

    // Create TCP pre-probing phase socket
    int tcp_pre_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_pre_sock < 0) {
        perror("TCP socket creation error");
        exit(EXIT_FAILURE);
    }

    // Create UDP probing phase socket
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("UDP socket creation error");
        exit(EXIT_FAILURE);
    }

    send_config_file(tcp_pre_sock, &config, config_file);
	close(tcp_pre_sock);
    
    send_udp_packets(udp_sock, &config);
    close(udp_sock);

	// Create TCP post-probing phase socket
    int tcp_post_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_post_sock < 0) {
    	perror("TCP socket creation error");
    	exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(tcp_post_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    	perror("setsockopt");
    	exit(EXIT_FAILURE);
    }

    struct sockaddr_in client_addr;
   	memset(&client_addr, 0, sizeof(client_addr));
   	client_addr.sin_family = AF_INET;
   	client_addr.sin_addr.s_addr = INADDR_ANY;
   	client_addr.sin_port = htons(config.tcp_post_probing_phase_port);

    if (bind(tcp_post_sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
    	perror("TCP bind failed");
    	exit(EXIT_FAILURE);
    }
    
     // Convert IP address
     if (inet_pton(AF_INET, config.server_ip_address, &client_addr.sin_addr) <= 0) {
         perror("Invalid TCP address");
         exit(EXIT_FAILURE);
     }

     sleep(10);
     
     if (connect(tcp_post_sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
         perror("TCP Connection Failed");
         exit(EXIT_FAILURE);
     }
     
    receive_detection_message(tcp_post_sock);
    close(tcp_post_sock);

    return 0;
}
