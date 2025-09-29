#include <iostream>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <fcntl.h>
#include <cstring>

bool isExecutable(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;
    return (st.st_mode & S_IXUSR);  // Check user executable bit
}

ino_t getInode(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return 0;
    return st.st_ino;
}

std::vector<int> findPIDsByInode(ino_t inode) {
    std::vector<int> pids;
    DIR* proc = opendir("/proc");
    if (!proc) return pids;

    struct dirent* entry;
    while ((entry = readdir(proc)) != nullptr) {
        if (!isdigit(entry->d_name[0])) continue;
        std::string pid_str = entry->d_name;
        std::string exe_path = "/proc/" + pid_str + "/exe";

        struct stat st;
        if (stat(exe_path.c_str(), &st) == 0) {
            if (st.st_ino == inode) {
                pids.push_back(std::stoi(pid_str));
            }
        }
    }
    closedir(proc);
    return pids;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <file_path>\n";
        return 1;
    }

    std::string path = argv[1];
    ino_t inode = getInode(path);

    if (inode == 0) {
        std::cerr << "Cannot stat file\n";
        return 1;
    }

    if (!isExecutable(path)) {
        std::cout << "File is not executable\n";
        return 0;
    }

    std::vector<int> pids = findPIDsByInode(inode);
    if (pids.empty()) {
        std::cout << "File is executable but no running process found\n";
    } else {
        std::cout << "File is executed by PID(s): ";
        for (int pid : pids) std::cout << pid << " ";
        std::cout << "\n";
    }

    return 0;
}
