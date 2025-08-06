#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/tmp/edr_control.sock"

int main() {
    int sock_fd;
    struct sockaddr_un addr;
    char password[128];

    printf("Enter password to stop EDR: ");
    scanf("%127s", password);

    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket failed");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path)-1);

    if (connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect failed");
        return 1;
    }

    write(sock_fd, password, strlen(password));
    close(sock_fd);

    printf("Stop command sent.\n");
    return 0;
}
