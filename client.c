#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP "169.254.47.121"
#define SERVER_PORT 8765 // Server destination port
#define CLIENT_PORT 9876 // Client source port
#define BUFFER_SIZE 1024

int main(int argc, char** argv) {
    int sock = 0;
    int valread;
    
    struct sockaddr_in serv_addr, client_addr;
    char buffer[BUFFER_SIZE] = {0};
    char message[BUFFER_SIZE];

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }
    
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(CLIENT_PORT);

    if (bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT); // Set server destination port

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        exit(EXIT_FAILURE);
    }

    while (1) {
        printf("Enter message to send to server (type 'quit' to exit): ");
        fgets(message, BUFFER_SIZE, stdin);

        // Check if user wants to quit
        if (strncmp(message, "quit", 4) == 0)
            break;

        // Send message to server
        send(sock, message, strlen(message), 0);
        printf("Message sent to server\n");

        // Read response from server
        valread = read(sock, buffer, BUFFER_SIZE);
        printf("Server response: %s\n", buffer);
    }

    close(sock);
    return 0;
}
