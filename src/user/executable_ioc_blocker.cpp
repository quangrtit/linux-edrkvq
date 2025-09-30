#include "executable_ioc_blocker.h"
#include "ioc_database.h"


ExecutableIOCBlocker::ExecutableIOCBlocker(volatile sig_atomic_t* external_exit, IOCDatabase &db)
    : fan_fd(-1), exiting(external_exit), ioc_db(db) {}

ExecutableIOCBlocker::~ExecutableIOCBlocker() {
    stop();
}

// void ExecutableIOCBlocker::add_policy(const std::string &path) {
//     __u64 key = get_inode_key(path.c_str());
//     if (key != 0) {
//         {
//             std::lock_guard<std::mutex> lock(cache_inode_policy_map_not_malicious_mutex);
//             cache_inode_policy_map_not_malicious[key] = true;
//         }
//
//     }
// }
void ExecutableIOCBlocker::add_policy(const __u64 &inode, __u64 ctime_sec, __u64 ctime_nsec) {
    if (inode != 0) {
        {
            std::lock_guard<std::mutex> lock(cache_inode_policy_map_not_malicious_mutex);
            cache_inode_policy_map_not_malicious[inode] = std::pair<__u64,__u64>(ctime_sec, ctime_nsec);
        }
        
    }
}
void ExecutableIOCBlocker::remove_policy(const __u64 &inode) {
    if (inode != 0) {
        {
            std::lock_guard<std::mutex> lock(cache_inode_policy_map_not_malicious_mutex);
            auto it = cache_inode_policy_map_not_malicious.find(inode);
            if(it != cache_inode_policy_map_not_malicious.end()) {
                cache_inode_policy_map_not_malicious.erase(it);
            }
        }
        
    }
}
bool ExecutableIOCBlocker::start() {
    if (fan_fd >= 0) return false; // already started
    fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);
    if (fan_fd < 0) return false;
    enumerate_mounts_and_mark();
    if (fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_OPEN_EXEC_PERM, AT_FDCWD, "/") < 0) {
        perror("fanotify_mark add /");
        close(fan_fd);
        fan_fd = -1;
        return false;
    }
    worker_thread = std::thread(&ExecutableIOCBlocker::loop, this);
    return true;
}

void ExecutableIOCBlocker::stop() {
    if (worker_thread.joinable()) worker_thread.join();
    if (fan_fd >= 0) {
        close(fan_fd);
        fan_fd = -1;
    }
}
bool ExecutableIOCBlocker::check_exe_malicious(const char* real_path, IOCDatabase& ioc_db) {
    
    auto start = std::chrono::high_resolution_clock::now();
    bool malicious;
    __u64 file_key = get_inode_key(real_path);
    // check cache file not malicious
    {
        std::lock_guard<std::mutex> lock(cache_inode_policy_map_not_malicious_mutex);
        if(cache_inode_policy_map_not_malicious.count(file_key) <= 0) {
            malicious = false;
        }
        else {
            auto it = cache_inode_policy_map_not_malicious.find(file_key);
            if(it != cache_inode_policy_map_not_malicious.end()) {
                __u64 ctime_sec = it->second.first;
                __u64 ctime_nsec = it->second.second;
                // std::cerr << "have: " << real_path << " " << ctime_sec << " " << ctime_nsec << "\n";
                struct stat st;
                if (stat(real_path, &st) == 0) {
                    if(st.st_ctim.tv_sec == ctime_sec && st.st_ctim.tv_nsec == ctime_nsec) {
                        // std::cerr << "File not changed, skip hash check: " << real_path << "\n";
                        return false; // file not change, not malicious
                    }
                }
            }
        }
    }
    // check file size before hash
    __u64 file_size = get_file_size(real_path);
    if (file_size == 0) {
        std::cerr << "File size is zero " << real_path << "\n";
        return false; 
    }
    // BEGIN: Added ELF heuristic scan
    if (!malicious) {
        // Call quick_scan_elf to check for suspicious ELF structure
        ScanResult elf_result = quick_scan_elf(real_path);
        if (elf_result.suspicious) {
            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::milli> elapsed = end - start;
            std::cerr << "Suspicious ELF file: " << real_path << " (Score: " << elf_result.score << ", Time: " << elapsed.count() << " ms)\n";
            for (const auto& reason : elf_result.reasons) {
                std::cerr << " - Reason: " << reason << "\n";
            }
        }
        // Check if file is large; if so, skip hash check
        if (file_size > LIMIT_FILE_SIZE && elf_result.suspicious) {
            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::milli> elapsed = end - start;
            std::cerr << "Large file (" << file_size / (1024.0 * 1024.0) << " MB), skipping hash check: " << real_path << " (Time: " << elapsed.count() << " ms)\n";
            malicious = elf_result.suspicious;
            return malicious; // Return current malicious status (likely false)
        }
    }
    // END: Added ELF heuristic scan
    if(!malicious && file_size <= LIMIT_FILE_SIZE) {
        std::string hash_check = calculate_sha256_fast(real_path);   
        // check malicious
        IOCMeta result;
        malicious = ioc_db.get_file_hash(hash_check, result); 
        if(malicious) { // cache malicious
            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::milli> elapsed = end - start;        
            std::cerr << "malicious file: " << real_path << " and time to hash file: " << elapsed.count() << " ms\n";
            // get ctime_sec and ctime_nsec
            
        }
        else {
            struct stat st;
            if (stat(real_path, &st) == 0) {
                __u64 ctime_sec = st.st_ctim.tv_sec;
                __u64 ctime_nsec = st.st_ctim.tv_nsec;
                // std::cerr << "add key: " << real_path << " " << ctime_sec << " " << ctime_nsec << "\n";
                add_policy(file_key, ctime_sec, ctime_nsec);
            }
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;
    // printf("Time to hash file %s with size %.3f MB: %.3f ms\n", real_path, file_size / (1024.0 * 1024.0), elapsed.count());
    std::cerr << "check file: " << real_path << " malicious: " << malicious << " size: " << file_size / (1024.0 * 1024.0) << " MB time: " << elapsed.count() << " ms\n";
    return malicious;
}
bool ExecutableIOCBlocker::add_mount(const std::string &path, const MountInfo& mount_info) {
    if (fan_fd < 0) return false;
    if (fanotify_mark(fan_fd,
                        FAN_MARK_ADD | FAN_MARK_MOUNT,
                        FAN_OPEN_EXEC_PERM,
                        AT_FDCWD,
                        path.c_str()) < 0) {
        perror(("fanotify_mark add " + path).c_str());
        return false;
    }
    mount_cache[path] = mount_info;
    // std::cerr << "[+] Add mount: " << path << "\n";
    return true;
}
bool ExecutableIOCBlocker::remove_mount(const std::string &path) {
    // return false;
    if (fan_fd < 0) return false;

    auto it = mount_cache.find(path);
    if(it != mount_cache.end()) {
        mount_cache.erase(it);
    }
    else {
        return false;
    }

    if (fanotify_mark(fan_fd, FAN_MARK_REMOVE | FAN_MARK_MOUNT,
                      FAN_OPEN_EXEC_PERM, AT_FDCWD, path.c_str()) < 0) {
        perror("fanotify_mark remove");
        return false;
    }
    // std::cerr << "[+] Remove mount: " << path << "\n";
    return true;
}
void ExecutableIOCBlocker::enumerate_mounts_and_mark() {
    std::ifstream mounts("/proc/self/mountinfo");
    if (!mounts.is_open()) {
        perror("open /proc/self/mountinfo");
        return;
    }

    std::string line;
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string mount_id, parent_id, major_minor, root, mount_point;
        MountInfo mount_info = {};
        if (!(iss >> mount_id >> parent_id >> major_minor >> root >> mount_point)) {
            continue;
        }

        // int major = 0, minor = 0;
        // sscanf(major_minor.c_str(), "%d:%d", &major, &minor);
        // uint64_t dev = ((uint64_t)major << 32) | minor;

        std::string token;
        while (iss >> token && token != "-");

        std::string fstype, devname;
        if (!(iss >> fstype >> devname)) {
            devname = "unknown";
        }
        mount_info.dev_name = devname;
        mount_info.fs_type = fstype;
        add_mount(mount_point, mount_info);
    }
    // for(auto path: mount_cache) {
    //     std::cerr << "mountpoint: " << path.first << std::endl;
    // }
}
// static bool is_system_critical_file(const char* path) {
//     static const char* critical_paths[] = {
//         "/usr/bin/systemd",
//         "/usr/lib/systemd/",
//         "/sbin/init",
//         "/usr/bin/dbus-daemon",
//         "/usr/bin/gnome-shell",
//         "/usr/bin/Xorg",
//         nullptr
//     };
    
//     for (int i = 0; critical_paths[i] != nullptr; i++) {
//         if (strncmp(path, critical_paths[i], strlen(critical_paths[i])) == 0) {
//             return true;
//         }
//     }
    
//     return false;
// }
void ExecutableIOCBlocker::loop() {
    struct pollfd fds[1];
    fds[0].fd = fan_fd;
    fds[0].events = POLLIN;
    const int POLL_TIMEOUT_MS = 50;    
    const size_t BUF_SIZE = 8192;  
    char buffer[BUF_SIZE];
    while (*exiting == 0) {
        int ret = poll(fds, 1, POLL_TIMEOUT_MS);
        if (ret < 0) {
            if (errno == EINTR) continue;
            // perror("poll");
            break;
        }
        if (ret == 0) continue; 

        ssize_t len = read(fan_fd, buffer, sizeof(buffer));
        if (len <= 0) continue;
        struct fanotify_event_metadata *metadata;
        for (metadata = (struct fanotify_event_metadata *)buffer;
            FAN_EVENT_OK(metadata, len);
            metadata = FAN_EVENT_NEXT(metadata, len)) {
            if (metadata->mask & FAN_OPEN_EXEC_PERM) {

                struct fanotify_response response = {
                    .fd = metadata->fd,
                    .response = FAN_ALLOW  
                };
                
                char link_path[PATH_MAX];
                snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", metadata->fd);

                char real_path[PATH_MAX];
                ssize_t r = readlink(link_path, real_path, sizeof(real_path) - 1);
                
                if (r > 0) {
                    real_path[r] = '\0';
                    try {
                        // bool malicious = check_exe_malicious(real_path, ioc_db);
                        bool malicious = check_with_timeout(real_path, ioc_db, TIME_OUT_CHECK_FILE_MS);
                        if (malicious) {
                            printf("BLOCKED malicious file: %s\n", real_path);
                            response.response = FAN_DENY;
                        } else {
                      
                            response.response = FAN_ALLOW;
                        }
                    } catch (const std::exception& e) {
                        fprintf(stderr, "Error checking file %s: %s\n", real_path, e.what());
                        response.response = FAN_ALLOW;
                    }
                } 
                else {
            
                    response.response = FAN_ALLOW;
                }
                if (write(fan_fd, &response, sizeof(response)) < 0) {
                    perror("Failed to send fanotify response");
                }
                
                close(metadata->fd);
            }
        }
    }
}
bool ExecutableIOCBlocker::check_with_timeout(const char* real_path, IOCDatabase& db, int timeout_ms) {
    auto fut = std::async(std::launch::async, [&]() {
        return check_exe_malicious(real_path, db);
    });

    if (fut.wait_for(std::chrono::milliseconds(timeout_ms)) == std::future_status::ready) {
        return fut.get();
    } else {
        fprintf(stderr, "[Timeout] Checking %s took too long, default ALLOW\n", real_path);
        return false; 
    }
}

static bool path_has_bad_substr(const std::string &p) {
    static const std::vector<std::string> bad = {"/tmp/", "/var/tmp/", "/dev/shm/", "/.local/", "/home/"};
    for (auto &s : bad) if (p.find(s) != std::string::npos) return true;
    return false;
}

static bool is_absolute(const std::string &p) {
    return !p.empty() && p[0] == '/';
}

// BEGIN: Modified to reduce false positives for DT_NEEDED
static bool is_suspicious_library(const std::string &lib) {
    // Whitelist common system libraries
    static const std::vector<std::string> safe_libs = {
        "libc.so", "libm.so", "libdl.so", "libpthread.so",
        "libpcre2", "libz.so", "libcurl.so", "libssl.so", "libcrypto.so"
    };
    // Flag if library in suspicious paths or has truly malicious names
    if (path_has_bad_substr(lib)) return true;
    if (lib.find(".evil") != std::string::npos) return true; // Only flag clear malicious names
    for (const auto& safe : safe_libs) {
        if (lib.find(safe) != std::string::npos) return false;
    }
    return false; // Default to safe unless clearly suspicious
}
// END: Modified

static void add_reason(ScanResult &r, const std::string &msg, int points=10) {
    r.reasons.push_back(msg);
    r.score += points;
    r.suspicious = r.score >= 30; // Increased threshold to 30
}

static double calculate_entropy(const uint8_t* data, size_t size) {
    if (size == 0) return 0.0;
    int freq[256] = {0};
    for (size_t i = 0; i < size; ++i) freq[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = static_cast<double>(freq[i]) / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

static std::optional<std::vector<uint8_t>> pread_all(int fd, off_t offset, size_t len) {
    std::vector<uint8_t> buf;
    buf.resize(len);
    size_t off = 0;
    while (off < len) {
        ssize_t rd = pread(fd, buf.data()+off, len-off, offset+off);
        if (rd <= 0) return std::nullopt;
        off += rd;
    }
    return buf;
}

static std::optional<std::string> read_string_at(int fd, off_t offset, size_t maxlen=4096) {
    auto opt = pread_all(fd, offset, maxlen);
    if (!opt) return std::nullopt;
    auto &buf = *opt;
    std::string s;
    for (size_t i=0; i<buf.size(); ++i) {
        if (buf[i] == 0) break;
        s.push_back((char)buf[i]);
    }
    return s;
}

ScanResult quick_scan_elf(const std::string &path) {
    ScanResult res;
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        add_reason(res, "Cannot open file", 0); // Zero points for errors
        return res;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        add_reason(res, "fstat failed", 0);
        close(fd);
        return res;
    }

    if (path_has_bad_substr(path)) {
        add_reason(res, "File in suspicious location (e.g., /tmp, /home)", 20);
    }

    auto hdr_data_opt = pread_all(fd, 0, EI_NIDENT + 64);
    if (!hdr_data_opt) {
        add_reason(res, "Cannot read ELF header", 0);
        close(fd);
        return res;
    }
    auto &hdr_data = *hdr_data_opt;
    if (hdr_data.size() < EI_NIDENT) {
        add_reason(res, "File too small for ELF header", 0);
        close(fd);
        return res;
    }
    if (hdr_data[EI_MAG0] != ELFMAG0 || hdr_data[EI_MAG1] != ELFMAG1 || 
        hdr_data[EI_MAG2] != ELFMAG2 || hdr_data[EI_MAG3] != ELFMAG3) {
        add_reason(res, "Not an ELF file", 0);
        close(fd);
        return res;
    }

    int ei_class = hdr_data[EI_CLASS];
    int ei_data = hdr_data[EI_DATA];
    if (ei_data != ELFDATA2LSB) {
        add_reason(res, "Non-Little-endian ELF - not handled", 1);
    }

    if (ei_class == ELFCLASS64) {
        auto ehdr_opt = pread_all(fd, 0, sizeof(Elf64_Ehdr));
        if (!ehdr_opt) { add_reason(res, "Failed read Elf64_Ehdr", 0); close(fd); return res; }
        Elf64_Ehdr eh;
        memcpy(&eh, ehdr_opt->data(), sizeof(Elf64_Ehdr));

        if (eh.e_type != ET_EXEC && eh.e_type != ET_DYN && eh.e_type != ET_REL) {
            add_reason(res, "ELF type is not common executable/shared-object", 1);
        }
        if (eh.e_type != ET_DYN) {
            add_reason(res, "Not PIE (non-ET_DYN) - easier to exploit", 10);
        }
        if (eh.e_entry == 0) {
            add_reason(res, "Zero entry point - suspicious", 15);
        }

        if (eh.e_phoff == 0 || eh.e_phnum == 0) {
            add_reason(res, "No program headers", 5);
        } else {
            size_t ph_size = (size_t)eh.e_phentsize * (size_t)eh.e_phnum;
            if (ph_size > 10*1024*1024) {
                add_reason(res, "Program header table very large, skipping", 1);
            } else {
                auto pht_opt = pread_all(fd, eh.e_phoff, ph_size);
                if (!pht_opt) {
                    add_reason(res, "Cannot read PHT", 5);
                } else {
                    bool found_interp = false, has_gnu_stack = false, has_relro = false;
                    std::string interp_path;
                    std::vector<Elf64_Phdr> phdrs(eh.e_phnum);
                    for (size_t i = 0; i < eh.e_phnum; ++i) {
                        Elf64_Phdr ph;
                        memcpy(&ph, pht_opt->data() + i*eh.e_phentsize, sizeof(Elf64_Phdr));
                        phdrs[i] = ph;
                        if (ph.p_type == PT_INTERP) {
                            found_interp = true;
                            auto s = read_string_at(fd, ph.p_offset, 4096);
                            if (s) interp_path = *s;
                        }
                        if ((ph.p_flags & (PF_W|PF_X)) == (PF_W|PF_X)) {
                            add_reason(res, "Segment has both write and execute (W+X) - suspicious", 20);
                        }
                        if (ph.p_type == PT_GNU_STACK) {
                            has_gnu_stack = true;
                            if (ph.p_flags & PF_X) {
                                add_reason(res, "Executable stack (no NX) - suspicious", 20);
                            }
                        }
                        if (ph.p_type == PT_GNU_RELRO) {
                            has_relro = true;
                        }
                    }

                    bool ep_in_load = false;
                    for (auto &ph : phdrs) {
                        if (ph.p_type == PT_LOAD) {
                            Elf64_Addr seg_start = ph.p_vaddr;
                            Elf64_Addr seg_end = ph.p_vaddr + ph.p_memsz;
                            if (eh.e_entry >= seg_start && eh.e_entry < seg_end) {
                                ep_in_load = true;
                                break;
                            }
                        }
                    }
                    if (!ep_in_load && eh.e_entry != 0) {
                        add_reason(res, "Entry point not in PT_LOAD segment", 15);
                    }

                    if (found_interp) {
                        if (!is_absolute(interp_path)) {
                            add_reason(res, "PT_INTERP is not absolute path", 10);
                        } else if (path_has_bad_substr(interp_path)) {
                            add_reason(res, "PT_INTERP path contains suspicious substrings", 25);
                        } else {
                            static const std::vector<std::string> wh = {
                                "/lib64/ld-linux-x86-64.so.2",
                                "/lib/ld-linux-x86-64.so.2",
                                "/lib/ld-musl-x86_64.so.1",
                                "/usr/lib/ld-musl-x86_64.so.1"
                            };
                            if (std::find(wh.begin(), wh.end(), interp_path) == wh.end()) {
                                add_reason(res, "PT_INTERP not in common whitelist", 5);
                            }
                        }
                    } else if (eh.e_type == ET_EXEC) {
                        add_reason(res, "Executable without PT_INTERP (static?)", 5);
                    }

                    // BEGIN: Modified DT_NEEDED parsing
                    for (auto &ph : phdrs) {
                        if (ph.p_type == PT_DYNAMIC) {
                            size_t dyn_size = ph.p_filesz;
                            if (dyn_size > 5*1024*1024) { add_reason(res, "Dynamic segment extremely large", 1); continue; }
                            auto dyn_raw_opt = pread_all(fd, ph.p_offset, dyn_size);
                            if (!dyn_raw_opt) { add_reason(res, "Failed read PT_DYNAMIC", 1); continue; }
                            auto &dyn_raw = *dyn_raw_opt;
                            size_t n = dyn_size / sizeof(Elf64_Dyn);
                            Elf64_Addr dyn_str_vaddr = 0;
                            size_t dyn_str_size = 0;
                            std::vector<Elf64_Sxword> needed_offsets;
                            for (size_t i = 0; i < n; ++i) {
                                Elf64_Dyn d;
                                memcpy(&d, dyn_raw.data() + i*sizeof(Elf64_Dyn), sizeof(Elf64_Dyn));
                                if (d.d_tag == DT_NULL) break;
                                if (d.d_tag == DT_STRTAB) dyn_str_vaddr = (Elf64_Addr)d.d_un.d_ptr;
                                if (d.d_tag == DT_STRSZ) dyn_str_size = (size_t)d.d_un.d_val;
                                if (d.d_tag == DT_NEEDED) needed_offsets.push_back(d.d_un.d_val);
                            }
                            off_t dynstr_file_offset = 0;
                            if (dyn_str_vaddr != 0) {
                                for (auto &phl : phdrs) {
                                    if (phl.p_type == PT_LOAD && dyn_str_vaddr >= phl.p_vaddr && 
                                        dyn_str_vaddr < phl.p_vaddr + phl.p_memsz) {
                                        dynstr_file_offset = phl.p_offset + (dyn_str_vaddr - phl.p_vaddr);
                                        break;
                                    }
                                }
                            }
                            if (dynstr_file_offset != 0 && dyn_str_size > 0) {
                                auto dynstr_opt = pread_all(fd, dynstr_file_offset, dyn_str_size);
                                if (dynstr_opt) {
                                    auto &dynstr = *dynstr_opt;
                                    for (auto offset : needed_offsets) {
                                        if (offset < dynstr.size()) {
                                            std::string lib((char*)dynstr.data() + offset);
                                            if (is_suspicious_library(lib)) {
                                                add_reason(res, "DT_NEEDED contains suspicious library: " + lib, 25);
                                            }
                                        }
                                    }
                                    std::string all((char*)dynstr.data(), dynstr.size());
                                    if (all.find("/tmp/") != std::string::npos) {
                                        add_reason(res, "DT_RPATH/DT_RUNPATH contains /tmp", 30);
                                    }
                                }
                            }
                        }
                    }
                    // END: Modified DT_NEEDED parsing

                    if (!has_gnu_stack) {
                        add_reason(res, "Missing PT_GNU_STACK - NX status unknown", 10);
                    }
                    if (!has_relro) {
                        add_reason(res, "Missing PT_GNU_RELRO - GOT vulnerable", 10);
                    }
                }
            }
        }

        if (eh.e_shoff == 0 || eh.e_shnum == 0) {
            add_reason(res, "Stripped sections - potentially suspicious", 10);
        } else {
            size_t sht_size = (size_t)eh.e_shentsize * (size_t)eh.e_shnum;
            if (sht_size < 100*1024) {
                auto sht_opt = pread_all(fd, eh.e_shoff, sht_size);
                if (sht_opt) {
                    if (eh.e_shstrndx < eh.e_shnum) {
                        Elf64_Shdr shstr;
                        memcpy(&shstr, sht_opt->data() + eh.e_shstrndx*eh.e_shentsize, sizeof(Elf64_Shdr));
                        off_t shstr_file_off = shstr.sh_offset;
                        size_t shstr_size = (size_t)shstr.sh_size;
                        if (shstr_file_off != 0 && shstr_size > 0 && shstr_size < 10*1024*1024) {
                            auto shstr_opt = pread_all(fd, shstr_file_off, shstr_size);
                            if (shstr_opt) {
                                auto &shstr = *shstr_opt;
                                for (size_t i = 0; i < eh.e_shnum; ++i) {
                                    Elf64_Shdr sh;
                                    memcpy(&sh, sht_opt->data() + i*eh.e_shentsize, sizeof(Elf64_Shdr));
                                    std::string name;
                                    if (sh.sh_name < shstr.size()) {
                                        name = std::string((const char*)shstr.data() + sh.sh_name);
                                    }
                                    if (!name.empty()) {
                                        if (name.find(".evil") != std::string::npos || name.find(".note.evil") != std::string::npos) {
                                            add_reason(res, "Suspicious section name: " + name, 30);
                                        }
                                        if (name == ".init_array" && sh.sh_size > 256) {
                                            add_reason(res, ".init_array large - possible pre-main code", 10);
                                        }
                                        // BEGIN: Modified executable section check
                                        if (sh.sh_flags & SHF_EXECINSTR) {
                                            // Only flag non-standard executable sections
                                            if (name != ".text" && name != ".init" && name != ".fini" &&
                                                name != ".plt" && name != ".plt.got" && name != ".plt.sec") {
                                                add_reason(res, "Non-standard executable section: " + name, 10);
                                            }
                                            // Entropy check for .text or suspicious executable sections
                                            if (name == ".text" || (sh.sh_flags & SHF_EXECINSTR)) {
                                                size_t sample_size = std::min<size_t>(1024, sh.sh_size);
                                                auto text_opt = pread_all(fd, sh.sh_offset, sample_size);
                                                if (text_opt) {
                                                    double ent = calculate_entropy(text_opt->data(), sample_size);
                                                    if (ent > 6.0) {
                                                        add_reason(res, "High entropy in " + name + " - possible packer", 15);
                                                    }
                                                }
                                            }
                                        }
                                        // END: Modified
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        close(fd);
        return res;
    } else if (ei_class == ELFCLASS32) {
        auto ehdr_opt = pread_all(fd, 0, sizeof(Elf32_Ehdr));
        if (!ehdr_opt) { add_reason(res, "Failed read Elf32_Ehdr", 0); close(fd); return res; }
        Elf32_Ehdr eh;
        memcpy(&eh, ehdr_opt->data(), sizeof(Elf32_Ehdr));
        if (eh.e_type != ET_DYN) {
            add_reason(res, "Not PIE (non-ET_DYN) - easier to exploit", 10);
        }
        if (eh.e_phoff == 0 || eh.e_phnum == 0) {
            add_reason(res, "No program headers (32-bit)", 5);
        } else {
            size_t ph_size = (size_t)eh.e_phentsize * (size_t)eh.e_phnum;
            if (ph_size < 10*1024*1024) {
                auto pht_opt = pread_all(fd, eh.e_phoff, ph_size);
                if (pht_opt) {
                    bool has_gnu_stack = false, has_relro = false;
                    std::vector<Elf32_Phdr> phdrs(eh.e_phnum);
                    for (size_t i = 0; i < eh.e_phnum; ++i) {
                        Elf32_Phdr ph;
                        memcpy(&ph, pht_opt->data()+i*eh.e_phentsize, sizeof(Elf32_Phdr));
                        phdrs[i] = ph;
                        if ((ph.p_flags & (PF_W|PF_X)) == (PF_W|PF_X)) {
                            add_reason(res, "Segment has both write and execute (W+X) - suspicious", 20);
                        }
                        if (ph.p_type == PT_INTERP) {
                            auto s = read_string_at(fd, ph.p_offset, 4096);
                            if (s) {
                                std::string interp = *s;
                                if (!is_absolute(interp)) add_reason(res, "PT_INTERP not absolute (32-bit)", 10);
                                if (path_has_bad_substr(interp)) add_reason(res, "PT_INTERP contains suspicious path (32-bit)", 25);
                            }
                        }
                        if (ph.p_type == PT_GNU_STACK) {
                            has_gnu_stack = true;
                            if (ph.p_flags & PF_X) {
                                add_reason(res, "Executable stack (no NX) - suspicious", 20);
                            }
                        }
                        if (ph.p_type == PT_GNU_RELRO) {
                            has_relro = true;
                        }
                    }
                    if (!has_gnu_stack) {
                        add_reason(res, "Missing PT_GNU_STACK - NX status unknown", 10);
                    }
                    if (!has_relro) {
                        add_reason(res, "Missing PT_GNU_RELRO - GOT vulnerable", 10);
                    }
                }
            }
        }
        if (eh.e_shoff == 0 || eh.e_shnum == 0) {
            add_reason(res, "Stripped sections - potentially suspicious", 10);
        }
        close(fd);
        return res;
    } else {
        add_reason(res, "Unknown ELF class", 2);
        close(fd);
        return res;
    }
}