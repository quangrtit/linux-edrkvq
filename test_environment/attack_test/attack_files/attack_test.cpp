#include <iostream>
#include <fstream>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <cstring>

const char* target_path = "/home/ubuntu/lib/vcs-ajiant-edr/test_environment/attack_test/test_file_vcs1.txt";
const char* renamed_path = "/home/ubuntu/lib/vcs-ajiant-edr/test_environment/attack_test/test_file_renamed.txt";

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
    else {
        std::cerr << "Unknown test case: " << arg << "\n";
        return 1;
    }

    std::cout << "Test case [" << arg << "] executed.\n";
    return 0;
}
