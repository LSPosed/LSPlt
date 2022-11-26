#pragma once

#include <sys/types.h>

#include <string_view>

namespace lsplt {
inline namespace v1 {
[[deprecated(
      "This hooks multiple functions at once, which makes the backup not accurate. Use register_hook with the first argument as ino_t instead."),
  maybe_unused]] bool
RegisterHook(std::string_view regex, std::string_view symbol, void *callback, void **backup);

[[maybe_unused]] bool RegisterHook(ino_t ino, std::string_view symbol, void *callback,
                                   void **backup);

[[deprecated("This is used with regex version of RegisterHook, which is deprecated."),
  maybe_unused]] void
IgnoreHook(std::string_view regex, std::string_view symbol);

[[deprecated("This is used with regex version of RegisterHook, which is deprecated."),
  maybe_unused]] void
IgnoreHook(ino_t ino, std::string_view symbol);

[[maybe_unused]] bool CommitHook();

[[maybe_unused]] bool InvalidateBackup();
}  // namespace v1
}  // namespace lsplt
