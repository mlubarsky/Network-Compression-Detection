#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8765
#define UDP_PAYLOAD_SIZE 1000
#define NUM_UDP_PACKETS 6000

void send_config(int tcp_sock, const char *config_file) {
    FILE *file = fopen(config_file, "r");
    if (!file) {
        perror("Failed to open config file");
        exit(EXIT_FAILURE);
    }

    char buffer[1024];
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

void send_udp_packets(int udp_sock) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    // Send low entropy UDP packets
    for (int i = 0; i < NUM_UDP_PACKETS; i++) {
        char payload[UDP_PAYLOAD_SIZE];
        memset(payload, 0, sizeof(payload)); // Fill payload with zeros
        sendto(udp_sock, payload, sizeof(payload), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    }

    // Wait for Inter-Measurement Time

    sleep(15); // Wait for 15 seconds

    // Send high entropy UDP packets
    for (int i = 0; i < NUM_UDP_PACKETS; i++) {
        char payload[UDP_PAYLOAD_SIZE];
        // Generate random payload here (not implemented in this example)
        sendto(udp_sock, payload, sizeof(payload), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <config_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    char *config_file = argv[1];

    int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock < 0) {
        perror("TCP socket creation error");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid TCP address");
        exit(EXIT_FAILURE);
    }

    if (connect(tcp_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("TCP Connection Failed");
        exit(EXIT_FAILURE);
    }

    send_config(tcp_sock, config_file);
    close(tcp_sock);

    // Create UDP socket
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("UDP socket creation error");
        exit(EXIT_FAILURE);
    }

    send_udp_packets(udp_sock);
    close(udp_sock);
    return 0;
}
