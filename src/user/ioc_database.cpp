#include "ioc_database.h"
#include <stdexcept>


std::string IOCMeta::serialize() const {
    return std::to_string(first_seen) + "," + std::to_string(last_seen) + "," + source;
}

IOCMeta IOCMeta::deserialize(const std::string& str) {
    IOCMeta meta;
    size_t pos1 = str.find(',');
    size_t pos2 = str.find(',', pos1 + 1);
    meta.first_seen = std::stoull(str.substr(0, pos1));
    meta.last_seen = std::stoull(str.substr(pos1 + 1, pos2 - pos1 - 1));
    meta.source = str.substr(pos2 + 1);
    return meta;
}

IOCDatabase::IOCDatabase(const std::string& path) {
    struct stat st = {0};
    if (stat(path.c_str(), &st) == -1) {
        if (mkdir(path.c_str(), 0755) != 0) {
            throw std::runtime_error("Failed to create folder for LMDB");
        }
    }
    if (mdb_env_create(&env) != 0)
        throw std::runtime_error("Failed to create LMDB env");

    mdb_env_set_maxdbs(env, 10);

    // add new 
    if (mdb_env_set_mapsize(env, 1024UL * 1024 * 1024) != 0)
        throw std::runtime_error("Failed to set LMDB map size");

    if (mdb_env_open(env, path.c_str(), 0, 0664) != 0)
        throw std::runtime_error("Failed to open LMDB env");

    MDB_txn* txn;
    int rc = mdb_txn_begin(env, nullptr, 0, &txn);
    if (rc != 0) throw std::runtime_error("Failed to begin LMDB txn");

    rc = mdb_dbi_open(txn, "file_hash_map", MDB_CREATE, &file_hash_dbi);
    if (rc != 0) { mdb_txn_abort(txn); throw std::runtime_error("Failed to open file_hash_map"); }

    rc = mdb_dbi_open(txn, "ip_map", MDB_CREATE, &ip_dbi);
    if (rc != 0) { mdb_txn_abort(txn); throw std::runtime_error("Failed to open ip_map"); }

    rc = mdb_txn_commit(txn);
    if (rc != 0) throw std::runtime_error("Failed to commit LMDB txn");
}
IOCDatabase::~IOCDatabase() {
    mdb_dbi_close(env, file_hash_dbi);
    mdb_dbi_close(env, ip_dbi);
    mdb_env_close(env);
}

void IOCDatabase::add_entry(MDB_dbi dbi, const std::string& key, const IOCMeta& meta) {
    MDB_txn* txn;
    mdb_txn_begin(env, nullptr, 0, &txn);

    MDB_val k, v;
    k.mv_size = key.size();
    k.mv_data = (void*)key.data();
    std::string s = meta.serialize();
    v.mv_size = s.size();
    v.mv_data = (void*)s.data();

    if(mdb_put(txn, dbi, &k, &v, 0) != 0) {
        printf("Failed to put key: %s\n", key.c_str());
    }
    mdb_txn_commit(txn);
}
void IOCDatabase::add_entries_batch(MDB_dbi dbi, const std::vector<std::pair<std::string, IOCMeta>>& batch) {
    MDB_txn* txn;
    mdb_txn_begin(env, nullptr, 0, &txn);

    for (auto& [key, meta] : batch) {
        MDB_val k, v;
        k.mv_size = key.size();
        k.mv_data = (void*)key.data();
        std::string s = meta.serialize();
        v.mv_size = s.size();
        v.mv_data = (void*)s.data();

        int rc = mdb_put(txn, dbi, &k, &v, MDB_NOOVERWRITE); 
        if(rc != 0 && rc != MDB_KEYEXIST)
            std::cerr << "Failed to put key: " << key << "\n";
    }

    mdb_txn_commit(txn);
}
bool IOCDatabase::get_entry(MDB_dbi dbi, const std::string& key, IOCMeta& meta) {
    MDB_txn* txn;
    mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);

    MDB_val k, v;
    k.mv_size = key.size();
    k.mv_data = (void*)key.data();

    int rc = mdb_get(txn, dbi, &k, &v);
    if(rc != 0) {
        mdb_txn_abort(txn);
        return false;
    }

    meta = IOCMeta::deserialize(std::string((char*)v.mv_data, v.mv_size));
    mdb_txn_abort(txn);
    return true;
}
bool IOCDatabase::delete_entry(MDB_dbi dbi, const std::string& key) {
    MDB_txn* txn;
    int rc = mdb_txn_begin(env, nullptr, 0, &txn);  
    if (rc != 0) {
        std::cerr << "Failed to begin transaction for delete\n";
        return false;
    }

    MDB_val k;
    k.mv_size = key.size();
    k.mv_data = (void*)key.data();

    rc = mdb_del(txn, dbi, &k, nullptr); 
    if (rc != 0 && rc != MDB_NOTFOUND) {
        std::cerr << "Failed to delete key: " << key << "\n";
        mdb_txn_abort(txn);
        return false;
    }

    mdb_txn_commit(txn);
    return true;
}

// func 
bool IOCDatabase::delete_file_hash(const std::string& hash) {
    return delete_entry(file_hash_dbi, hash);
}

bool IOCDatabase::delete_ip(const std::string& ip) {
    return delete_entry(ip_dbi, ip);
}
void IOCDatabase::add_file_hash(const std::string& hash, const IOCMeta& meta) {
    add_entry(file_hash_dbi, hash, meta);
}

void IOCDatabase::add_ip(const std::string& ip, const IOCMeta& meta) {
    add_entry(ip_dbi, ip, meta);
}

bool IOCDatabase::get_file_hash(const std::string& hash, IOCMeta& meta) {
    return get_entry(file_hash_dbi, hash, meta);
}

bool IOCDatabase::get_ip(const std::string& ip, IOCMeta& meta) {
    return get_entry(ip_dbi, ip, meta);
}
void IOCDatabase::dump_database_info() {
    MDB_txn* txn;
    mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);

    MDB_stat stat;
    if (mdb_stat(txn, file_hash_dbi, &stat) == 0) {
        std::cerr << "[File Hash DB]\n";
        std::cerr << "  Entries: " << stat.ms_entries << "\n";
        std::cerr << "  Page Size: " << stat.ms_psize << " bytes\n";
        std::cerr << "  DB Size: " << (stat.ms_entries * stat.ms_psize) << " bytes (approx)\n";
    }

    if (mdb_stat(txn, ip_dbi, &stat) == 0) {
        std::cerr << "[IP DB]\n";
        std::cerr << "  Entries: " << stat.ms_entries << "\n";
        std::cerr << "  Page Size: " << stat.ms_psize << " bytes\n";
        std::cerr << "  DB Size: " << (stat.ms_entries * stat.ms_psize) << " bytes (approx)\n";
    }

    std::cerr << "\n=== File Hash Records ===\n";
    {
        MDB_cursor* cursor;
        mdb_cursor_open(txn, file_hash_dbi, &cursor);
        MDB_val key, data;
        while (mdb_cursor_get(cursor, &key, &data, MDB_NEXT) == 0) {
            std::string k((char*)key.mv_data, key.mv_size);
            std::string v((char*)data.mv_data, data.mv_size);
            std::cerr << "Key: " << k << "\n";
            IOCMeta meta = IOCMeta::deserialize(v);
            std::cerr << "  First Seen: " << meta.first_seen
                      << ", Last Seen: " << meta.last_seen
                      << ", Source: " << meta.source << "\n";
        }
        mdb_cursor_close(cursor);
    }

    std::cerr << "\n=== IP Records ===\n";
    {
        MDB_cursor* cursor;
        mdb_cursor_open(txn, ip_dbi, &cursor);
        MDB_val key, data;
        while (mdb_cursor_get(cursor, &key, &data, MDB_NEXT) == 0) {
            std::string k((char*)key.mv_data, key.mv_size);
            std::string v((char*)data.mv_data, data.mv_size);
            std::cerr << "Key: " << k << "\n";
            IOCMeta meta = IOCMeta::deserialize(v);
            std::cerr << "  First Seen: " << meta.first_seen
                      << ", Last Seen: " << meta.last_seen
                      << ", Source: " << meta.source << "\n";
        }
        mdb_cursor_close(cursor);
    }

    mdb_txn_abort(txn);
}

void update_database(IOCDatabase& db) {

    IOCMeta meta{static_cast<uint64_t>(time(nullptr)),
                 static_cast<uint64_t>(time(nullptr)),
                 "user_upload"};

    std::ifstream file_hash(IOC_HASH_FILE_PATH);
    std::string line;
    std::vector<std::pair<std::string, IOCMeta>> batch;
    int count_record = 0;
    while (std::getline(file_hash, line)) {
        if (line.empty()) continue;
        batch.emplace_back(line, meta);
        ++count_record;
        if(batch.size() >= 1000) {  // batch 1000 key
            db.add_entries_batch(db.file_hash_dbi, batch);
            batch.clear();
        }
    }
    if(!batch.empty()) db.add_entries_batch(db.file_hash_dbi, batch);
    file_hash.close();

    std::ifstream file_ip(IOC_IP_PATH);
    batch.clear();
    while (std::getline(file_ip, line)) {
        if(line.empty()) continue;
        batch.emplace_back(line, meta);
        if(batch.size() >= 1000) {
            db.add_entries_batch(db.ip_dbi, batch);
            batch.clear();
        }
    }
    if(!batch.empty()) db.add_entries_batch(db.ip_dbi, batch);
    file_ip.close();
    printf("total recorn hash file: %d\n", count_record);
}
