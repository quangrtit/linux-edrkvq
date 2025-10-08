#include <iostream>
#include <csignal>
#include <unistd.h>

int main() {
    while(1) {
        pid_t pid;
        std::cout << "Nhập PID cần kill: ";
        std::cin >> pid;

        if (kill(pid, SIGKILL) == 0) {
            std::cout << "Đã gửi SIGKILL tới PID " << pid << "\n";
        } else {
            perror("Lỗi khi kill");
        }
    }
    return 0;
}
