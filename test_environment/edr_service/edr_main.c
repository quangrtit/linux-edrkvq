#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/tmp/edr_control.sock"
#define PASSWORD "edrpassword123"

void create_control_socket() {
    int server_fd;
    struct sockaddr_un addr;

    unlink(SOCKET_PATH);

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path)-1);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        exit(1);
    }

    if (listen(server_fd, 1) < 0) {
        perror("listen failed");
        exit(1);
    }

    printf("[EDR] Listening for control commands...\n");

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) continue;

        char buffer[128] = {0};
        read(client_fd, buffer, sizeof(buffer)-1);

        if (strncmp(buffer, PASSWORD, strlen(PASSWORD)) == 0) {
            printf("[EDR] Received valid stop command. Exiting...\n");
            close(client_fd);
            break;
        } else {
            printf("[EDR] Invalid password attempt: %s\n", buffer);
        }
        close(client_fd);
    }

    unlink(SOCKET_PATH);
}

int main() {
    create_control_socket();

    // EDR main loop simulation
    while (1) {
        printf("[EDR] Monitoring system events...\n");
        sleep(5);
    }

    return 0;
}
