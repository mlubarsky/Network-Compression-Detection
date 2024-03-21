#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP "169.254.47.121"
#define SERVER_PORT 8765
#define BUFFER_SIZE 1024

int main(int argc, char** argv) {
    int tcp_sock = 0;
    struct sockaddr_in serv_addr_tcp;
    //char buffer[BUFFER_SIZE] = {0};
    char *config_file = argv[1];

    if ((tcp_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("TCP socket creation error");
        exit(EXIT_FAILURE);
    }

	memset(&serv_addr_tcp, 0, sizeof(serv_addr_tcp));
    serv_addr_tcp.sin_family = AF_INET;
    serv_addr_tcp.sin_port = htons(SERVER_PORT); // Set server destination port

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr_tcp.sin_addr) <= 0) {
        perror("Invalid TCP address/ Address not supported");
        exit(EXIT_FAILURE);
    }

    if (connect(tcp_sock, (struct sockaddr *)&serv_addr_tcp, sizeof(serv_addr_tcp)) < 0) {
        perror("TCP Connection Failed");
        exit(EXIT_FAILURE);
    }

    // Send message to server
    send(tcp_sock, config_file, strlen(config_file), 0);
    printf("Message sent to server\n");

    close(tcp_sock);
    return 0;
}
