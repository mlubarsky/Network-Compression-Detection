#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_PORT 8765
#define BUFFER_SIZE 1024

int main(int argc, char** argv) {
    int server_fd;
    int new_socket;
    int valread;
    
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    char *message = "Message received";

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket to port 8765
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(SERVER_PORT);

    // Attach socket to  port 8765
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        	perror("accept");
        	exit(EXIT_FAILURE);
        }

        while ((valread = read(new_socket, buffer, BUFFER_SIZE)) > 0) {
        	printf("Message from client: %s\n", buffer);

        	// Send response to client
        	send(new_socket, message, strlen(message), 0);
        	printf("Response sent to client\n");

        	// Clear buffer
        	memset(buffer, 0, BUFFER_SIZE);
        }

        if (valread == 0) {
        	printf("Client disconnected\n");
        	close(new_socket);
        	break;
        }
    }

    close(server_fd);
    return 0;
}
