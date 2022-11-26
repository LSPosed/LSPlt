#include "include/lsplt.hpp"

#include <regex.h>
#include <sys/mman.h>

#include <array>
#include <cinttypes>
#include <list>
#include <map>
#include <mutex>
#include <vector>

#include "elf_util.hpp"

namespace {
struct RegisterInfo {
    ino_t inode;
    std::string symbol;
    void *callback;
    void **backup;
};

struct HookMapInfo : public lsplt::MapInfo {
    std::map<uintptr_t, uintptr_t> hooks;
    uintptr_t backup;
    std::unique_ptr<Elf> elf;
    [[nodiscard]] bool Match(const RegisterInfo &info) const { return info.inode == inode; }
};

class HookMapInfos : public std::map<uintptr_t, MapInfo, std::greater<>> {
public:
    static MapInfos ScanMapInfo() {
        constexpr static auto kPermLength = 5;
        constexpr static auto kMapEntry = 5;
        MapInfos info;
        auto maps =
            std::unique_ptr<FILE, decltype(&fclose)>{fopen("/proc/self/maps", "r"), &fclose};
        if (maps) {
            char *line = nullptr;
            size_t len = 0;
            ssize_t read;
            while ((read = getline(&line, &len, maps.get())) != -1) {
                uintptr_t start = 0;
                uintptr_t end = 0;
                uintptr_t off = 0;
                ino_t inode = 0;
                std::array<char, kPermLength> perm{'\0'};
                int path_off;
                if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %*x:%*x %lu %n%*s",
                           &start, &end, perm.data(), &off, &inode, &path_off) != kMapEntry) {
                    continue;
                }
                // we basically only care about r--p entry
                // and for offset == 0 it's an ELF header
                // and for offset != 0 it's what we hook
                // if (perm[0] != 'r') continue;
                if (perm[3] != 'p') continue;
                if (perm[2] == 'x') continue;
                // if (off != 0) continue;
                while (path_off < read && isspace(line[path_off])) path_off++;
                if (path_off >= read) continue;
                std::string path{line + path_off};
                if (path.empty()) continue;
                if (path[0] == '[') continue;

                info.emplace(start, MapInfo{std::move(path), inode, start, end, {}, 0, nullptr});
            }
            free(line);
        }
        return info;
    }

    // fiter out ignored
    void Filter(const std::list<RegisterInfo> &register_info) {
        for (auto iter = begin(); iter != end();) {
            const auto &info = iter->second;
            bool matched = false;
            for (const auto &reg : register_info) {
                if (info.Match(reg)) {
                    matched = true;
                    break;
                }
            }
            if (matched) {
                ++iter;
            } else {
                iter = erase(iter);
            }
        }
    }

    void Merge(MapInfos &old) {
        // merge with old map info
        for (auto &info : old) {
            if (info.second.backup) {
                erase(info.second.backup);
            }
            if (auto iter = find(info.first); iter != end()) {
                iter->second = std::move(info.second);
            } else {
                emplace(info.first, std::move(info.second));
            }
        }
    }

    bool DoHook(uintptr_t addr, uintptr_t callback, uintptr_t *backup) {
        auto iter = lower_bound(addr);
        if (iter == end()) return false;
        // iter.first < addr
        auto &info = iter->second;
        if (info.end <= addr) return false;
        if (!iter->second.backup) {
            auto len = info.end - info.start;
            // let os find a suitable address
            auto *backup_addr = mmap(nullptr, len, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
            if (backup_addr == MAP_FAILED) return false;
            if (auto *new_addr = mremap(reinterpret_cast<void *>(info.start), len, len,
                                        MREMAP_FIXED | MREMAP_MAYMOVE, backup_addr);
                new_addr == MAP_FAILED || new_addr != backup_addr) {
                return false;
            }
            if (auto *new_addr =
                    mmap(reinterpret_cast<void *>(info.start), len, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);
                new_addr == MAP_FAILED) {
                return false;
            }
            memcpy(reinterpret_cast<void *>(info.start), backup_addr, len);
            info.backup = reinterpret_cast<uintptr_t>(backup_addr);
        }
        auto *the_addr = reinterpret_cast<uintptr_t *>(addr);
        *backup = *the_addr;
        *the_addr = callback;
        if (auto hook_iter = info.hooks.find(addr); hook_iter != info.hooks.end()) {
            if (hook_iter->second == callback) info.hooks.erase(hook_iter);
        } else {
            info.hooks.emplace(addr, *backup);
        }
        if (info.hooks.empty()) {
            auto len = info.end - info.start;
            if (auto *new_addr =
                    mremap(reinterpret_cast<void *>(info.backup), len, len,
                           MREMAP_FIXED | MREMAP_MAYMOVE, reinterpret_cast<void *>(info.start));
                new_addr == MAP_FAILED || reinterpret_cast<uintptr_t>(new_addr) != info.start) {
                return false;
            }
            info.backup = 0;
        }
        return true;
    }

    bool DoHook(std::list<RegisterInfo> &register_info) {
        bool res = true;
        for (auto &[_, info] : *this) {
            for (auto iter = register_info.begin(); iter != register_info.end();) {
                const auto &reg = *iter;
                if (info.start != 0 || !info.Match(reg)) continue;
                if (!info.elf) info.elf = std::make_unique<Elf>(info.start);
                if (info.elf && info.elf->Valid()) {
                    for (auto addr : info.elf->FindPltAddr(reg.symbol)) {
                        res = DoHook(addr, reinterpret_cast<uintptr_t>(reg.callback),
                                     reinterpret_cast<uintptr_t *>(reg.backup)) &&
                              res;
                    }
                }
                iter = register_info.erase(iter);
            }
        }
        return res;
    }

    bool InvalidateBackup() {
        bool res = true;
        for (auto &[_, info] : *this) {
            if (!info.backup) continue;
            for (auto &[addr, backup] : info.hooks) {
                // store new address to backup since we don't need backup
                backup = *reinterpret_cast<uintptr_t *>(addr);
            }
            auto len = info.end - info.start;
            if (auto *new_addr =
                    mremap(reinterpret_cast<void *>(info.backup), len, len,
                           MREMAP_FIXED | MREMAP_MAYMOVE, reinterpret_cast<void *>(info.start));
                new_addr == MAP_FAILED || reinterpret_cast<uintptr_t>(new_addr) != info.start) {
                res = false;
                info.hooks.clear();
                continue;
            }
            for (auto &[addr, backup] : info.hooks) {
                *reinterpret_cast<uintptr_t *>(addr) = backup;
            }
            info.hooks.clear();
            info.backup = 0;
        }
        return res;
    }
};

std::mutex hook_mutex;
std::list<RegisterInfo> register_info;
MapInfos map_info;
}  // namespace

namespace lsplt {

std::vector<MapInfo> MapInfo::Scan() {
    constexpr static auto kPermLength = 5;
    constexpr static auto kMapEntry = 5;
    std::vector<MapInfo> info;
    auto maps = std::unique_ptr<FILE, decltype(&fclose)>{fopen("/proc/self/maps", "r"), &fclose};
    if (maps) {
        char *line = nullptr;
        size_t len = 0;
        ssize_t read;
        while ((read = getline(&line, &len, maps.get())) != -1) {
            uintptr_t start = 0;
            uintptr_t end = 0;
            uintptr_t off = 0;
            ino_t inode = 0;
            std::array<char, kPermLength> perm{'\0'};
            int path_off;
            if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %*x:%*x %lu %n%*s", &start,
                       &end, perm.data(), &off, &inode, &path_off) != kMapEntry) {
                continue;
            }
            // we basically only care about r--p entry
            // and for offset == 0 it's an ELF header
            // and for offset != 0 it's what we hook
            // if (perm[0] != 'r') continue;
            if (perm[3] != 'p') continue;
            if (perm[2] == 'x') continue;
            // if (off != 0) continue;
            while (path_off < read && isspace(line[path_off])) path_off++;
            if (path_off >= read) continue;
            std::string path{line + path_off};
            if (path.empty()) continue;
            if (path[0] == '[') continue;

            info.emplace(start, MapInfo{std::move(path), inode, start, end, {}, 0, nullptr});
        }
        free(line);
    }
    return info;
}
[[maybe_unused]] bool RegisterHook(ino_t ino, std::string_view symbol, void *callback,
                                   void **backup) {
    if (symbol.empty() || !callback) return false;

    std::unique_lock lock(hook_mutex);
    register_info.emplace_back(RegisterInfo{ino, std::string{symbol}, callback, backup});

    return true;
}

[[maybe_unused]] bool CommitHook() {
    std::unique_lock lock(hook_mutex);
    if (register_info.empty()) return true;

    auto new_map_info = MapInfos::ScanMapInfo();
    if (new_map_info.empty()) return false;

    new_map_info.Filter(register_info);

    new_map_info.Merge(map_info);
    // update to new map info
    map_info = std::move(new_map_info);

    return map_info.DoHook(register_info);
}

[[gnu::destructor]] [[maybe_unused]] bool InvalidateBackup() {
    std::unique_lock lock(hook_mutex);
    return map_info.InvalidateBackup();
}
}  // namespace lsplt
