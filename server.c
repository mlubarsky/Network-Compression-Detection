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
    
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("TCP socket failed");
        exit(EXIT_FAILURE);
    }


    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(SERVER_PORT);

    // Attach socket to  port 8765
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("TCP bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("TCP listen failed");
        exit(EXIT_FAILURE);
    }

    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
    	perror("TCP accept failed");
    	exit(EXIT_FAILURE);
    }

	int bytes_received = recv(new_socket, buffer, BUFFER_SIZE, 0);
	if (bytes_received < 0) {
		perror("TCP receieve failed");
		exit(EXIT_FAILURE);
	}

  	buffer[bytes_received] = '\0';
  	printf("Received configuration file contents from client: %s\n", buffer);

  	close(new_socket);
    close(server_fd);
    return 0;
}
