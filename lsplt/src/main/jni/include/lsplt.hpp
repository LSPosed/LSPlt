#pragma once

#include <sys/types.h>

#include <string>
#include <string_view>

namespace lsplt {
inline namespace v1 {

struct MapInfo {
    uintptr_t start;
    uintptr_t end;
    uint8_t perms;
    bool is_private;
    uintptr_t offset;
    dev_t dev;
    ino_t inode;
    std::string path;

    [[maybe_unused, gnu::visibility("default")]] static std::vector<MapInfo> Scan();
};

[[maybe_unused, gnu::visibility("default")]] bool RegisterHook(ino_t ino, std::string_view symbol,
                                                               void *callback, void **backup);

[[maybe_unused, gnu::visibility("default")]] bool CommitHook();

[[maybe_unused, gnu::visibility("default")]] bool InvalidateBackup();
}  // namespace v1
}  // namespace lsplt
