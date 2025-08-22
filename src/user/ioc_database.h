#ifndef _IOC_DATABASE_H
#define _IOC_DATABASE_H

#include "common_user.h"
#include <lmdb.h>
#include <iostream>
#include <fstream>
#include <sstream>
struct IOCMeta {
    uint64_t first_seen;
    uint64_t last_seen;
    std::string source;

    std::string serialize() const;
    static IOCMeta deserialize(const std::string& str);
};

class IOCDatabase {
public:
    IOCDatabase(const std::string& path);
    ~IOCDatabase();

    void add_file_hash(const std::string& hash, const IOCMeta& meta);
    void add_ip(const std::string& ip, const IOCMeta& meta);

    bool get_file_hash(const std::string& hash, IOCMeta& meta);
    bool get_ip(const std::string& ip, IOCMeta& meta);
    void add_entries_batch(MDB_dbi dbi, const std::vector<std::pair<std::string, IOCMeta>>& batch);
    void dump_database_info(); 

    bool delete_file_hash(const std::string& hash);
    bool delete_ip(const std::string& ip);
public:
    MDB_env* env;
    MDB_dbi file_hash_dbi;
    MDB_dbi ip_dbi;

    void add_entry(MDB_dbi dbi, const std::string& key, const IOCMeta& meta);
    
    bool get_entry(MDB_dbi dbi, const std::string& key, IOCMeta& meta);

    bool delete_entry(MDB_dbi dbi, const std::string& key);
    
};

void update_database(IOCDatabase& db);
#endif // _IOC_DATABASE_H