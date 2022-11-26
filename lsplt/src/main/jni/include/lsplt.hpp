#pragma once

#include <sys/types.h>

#include <string_view>

namespace lsplt {
inline namespace v1 {
[[maybe_unused, gnu::visibility("default")]] bool RegisterHook(ino_t ino, std::string_view symbol,
                                                               void *callback, void **backup);

[[maybe_unused, gnu::visibility("default")]] bool CommitHook();

[[maybe_unused, gnu::visibility("default")]] bool InvalidateBackup();
}  // namespace v1
}  // namespace lsplt
