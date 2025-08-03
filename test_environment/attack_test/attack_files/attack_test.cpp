#include <iostream>
#include <fstream>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

const char* target_path = "/home/ubuntu/lib/vcs-ajiant-edr/test_environment/attack_test/test_file_vcs1.txt";
const char* renamed_path = "/home/ubuntu/lib/vcs-ajiant-edr/test_environment/attack_test/test_file_renamed.txt";
const std::string SENTINEL_EDR_PATH = "/home/quang/myLib/vcs-ajiant-edr/build/SentinelEDR";
void write_file() {
    std::ofstream ofs(target_path, std::ios::app);
    ofs << "Appending new line.\n";
    ofs.close();
}

void modify_file() {
    std::ofstream ofs(target_path);
    ofs << "Overwritten content.\n";
    ofs.close();
}

void delete_file() {
    std::filesystem::remove(target_path);
}

void rename_file() {
    std::filesystem::rename(target_path, renamed_path);
}

void recreate_file() {
    std::ofstream ofs(target_path, std::ios::trunc);
    ofs << "Recreated file with new content.\n";
    ofs.close();
}

void chmod_file() {
    std::cout << "Result chmod: " << chmod(target_path, 0000) << "\n"; // danger
}

void mmap_write() {
    int fd = open(target_path, O_RDWR);
    if (fd < 0) {
        perror("open");
        return;
    }

    size_t length = 4096;
    char* data = (char*) mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (data == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return;
    }

    sprintf(data, "Modified via mmap!\n");
    msync(data, length, MS_SYNC);
    munmap(data, length);
    close(fd);
}

void open_write_only() {
    int fd = open(target_path, O_WRONLY);
    if (fd >= 0) {
        write(fd, "Direct write\n", 13);
        close(fd);
    }
}

void create_symlink() {
    const char* symlink_path = "/tmp/test_symlink";
    unlink(symlink_path);
    symlink(target_path, symlink_path);
}

void create_hardlink() {
    const char* hardlink_path = "/tmp/test_hardlink";
    unlink(hardlink_path);
    link(target_path, hardlink_path);
}


// Hàm mô phỏng việc cấp phát vùng nhớ ẩn danh với quyền RWX (Read, Write, Execute).
// Kẻ tấn công có thể dùng để tạo nơi chứa shellcode.
void anonymous_mmap_rwx_exploit() {
    size_t length = 4096;
    void* addr = mmap(NULL, length, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (addr == MAP_FAILED) {
        perror("anonymous mmap RWX failed");
        return;
    }
    std::cout << "Anonymous mmap RWX succeeded at " << addr << "\n";
    munmap(addr, length);
}

// Hàm mô phỏng việc thay đổi quyền của một vùng nhớ đã tồn tại thành RWX.
// Kẻ tấn công có thể dùng để biến vùng dữ liệu thành vùng thực thi.
void mprotect_rwx_exploit() {
    size_t length = 4096;
    void* addr = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (addr == MAP_FAILED) {
        perror("initial mmap failed");
        return;
    }

    if (mprotect(addr, length, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        perror("mprotect RWX failed");
    } else {
        std::cout << "mprotect RWX succeeded at " << addr << "\n";
    }

    munmap(addr, length);
}

// Hàm mô phỏng việc tiêm mã vào tiến trình SentinelEDR bằng ptrace.
// Đây là kỹ thuật tiêm mã từ xa vào một tiến trình đang chạy.
void remote_code_injection_sentinel_edr() {
    std::string target_path = "/home/quang/myLib/vcs-ajiant-edr/build/SentinelEDR";

    // Khởi chạy tiến trình SentinelEDR để làm mục tiêu
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork failed to start target process");
        return;
    }

    if (pid == 0) { // Child process: đóng vai trò là SentinelEDR
        execl(target_path.c_str(), target_path.c_str(), NULL);
        perror("exec SentinelEDR failed"); // Chỉ đến đây nếu exec thất bại
        _exit(1);
    } else { // Parent process: đóng vai trò là kẻ tấn công
        std::cout << "Started target process SentinelEDR with PID: " << pid << "\n";

        // Gắn vào tiến trình đích để chuẩn bị tiêm mã
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
            perror("ptrace attach failed");
            kill(pid, SIGKILL); // Kết thúc tiến trình đích nếu không gắn được
            return;
        }
        std::cout << "Successfully attached to target process PID: " << pid << "\n";

        // Đợi tiến trình đích dừng lại sau khi gắn
        waitpid(pid, NULL, 0);

        // Lấy các thanh ghi của tiến trình đích
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
            perror("ptrace getregs failed");
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            kill(pid, SIGKILL);
            return;
        }

        // === Phần này mô phỏng hành động tiêm mã vào bộ nhớ của SentinelEDR ===
        // Trong một cuộc tấn công thực tế, kẻ tấn công sẽ:
        // 1. Tìm hoặc cấp phát một vùng nhớ RWX trong SentinelEDR.
        // 2. Ghi shellcode vào vùng nhớ đó.
        // 3. Thay đổi con trỏ lệnh (RIP/EIP) của SentinelEDR để nhảy đến shellcode.
        // 4. Giải phóng hoặc tiếp tục tiến trình SentinelEDR.

        // Vì chúng ta không thực sự tiêm shellcode hay thay đổi luồng điều khiển
        // mà chỉ mô phỏng, ta sẽ chỉ in ra thông báo.
        std::cout << "Simulating memory manipulation inside SentinelEDR (e.g., mmap RWX or mprotect RWX).\n";
        std::cout << "In a real attack, shellcode would be written and executed here.\n";

        // === Kết thúc mô phỏng tiêm mã ===

        // Tháo gỡ ptrace và cho phép tiến trình đích tiếp tục
        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
            perror("ptrace detach failed");
            kill(pid, SIGKILL);
            return;
        }
        std::cout << "Successfully detached from target process PID: " << pid << "\n";

        // Đợi tiến trình đích hoàn thành hoặc kết thúc thủ công nếu cần
        waitpid(pid, NULL, 0); // Đợi SentinelEDR kết thúc nếu nó tự kết thúc
        std::cout << "Target process SentinelEDR completed.\n";
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: ./test_attack <test_case>\n";
        return 1;
    }

    std::string arg = argv[1];

    if (arg == "1" || arg == "write") write_file();
    else if (arg == "2" || arg == "modify") modify_file();
    else if (arg == "3" || arg == "delete") delete_file();
    else if (arg == "4" || arg == "rename") rename_file();
    else if (arg == "5" || arg == "recreate") recreate_file();
    else if (arg == "6" || arg == "chmod") chmod_file();
    else if (arg == "7" || arg == "mmap") mmap_write();
    else if (arg == "8" || arg == "openwrite") open_write_only();
    else if (arg == "9" || arg == "symlink") create_symlink();
    else if (arg == "10" || arg == "hardlink") create_hardlink();
    else if (arg == "11" || arg == "anonmmap") anonymous_mmap_rwx_exploit();
    else if (arg == "12" || arg == "mprotect") mprotect_rwx_exploit();
    else if (arg == "13" || arg == "remoteinject") remote_code_injection_sentinel_edr();
    else {
        std::cerr << "Unknown test case: " << arg << "\n";
        return 1;
    }

    std::cout << "Test case [" << arg << "] executed.\n";
    return 0;
}
