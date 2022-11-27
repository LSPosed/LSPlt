#pragma once

#include <sys/types.h>

#include <string>
#include <string_view>

/// \namespace namespace of LSPlt
namespace lsplt {
inline namespace v1 {

/// \struct MapInfo
/// \brief An entry that describes a line in /proc/self/maps. You can obtain a list of these entries
/// by calling #Scan().
struct MapInfo {
    /// \brief The start address of the memory region.
    uintptr_t start;
    /// \brief The end address of the memory region.
    uintptr_t end;
    /// \brief The permissions of the memory region. This is a bit mask of the following values:
    /// - PROT_READ
    /// - PROT_WRITE
    /// - PROT_EXEC
    uint8_t perms;
    /// \brief Whether the memory region is private.
    bool is_private;
    /// \brief The offset of the memory region.
    uintptr_t offset;
    /// \brief The device number of the memory region.
    /// Major can be obtained by #major()
    /// Minor can be obtained by #minor()
    dev_t dev;
    /// \brief The inode number of the memory region.
    ino_t inode;
    /// \brief The path of the memory region.
    std::string path;

    /// \brief Scans /proc/self/maps and returns a list of \ref MapInfo entries.
    /// This is useful to find out the inode of the library to hook.
    /// \return A list of \ref MapInfo entries.
    [[maybe_unused, gnu::visibility("default")]] static std::vector<MapInfo> Scan();
};

/// \brief Register a hook to a function.
/// \param inode The inode of the library to hook. You can obtain the inode by #stat() or by finding
/// the library in the list returned by #MapInfo::Scan().
/// \param symbol The function symbol to hook.
/// \param callback The callback function pointer to call when the function is called.
/// \param backup The backup function pointer which can call the original function. This is optional.
/// \return Whether the hook is successfully registered.
/// \note This function is thread-safe.
/// \note \p backup will not be available until #CommitHook() is called.
/// \note \p backup will be nullptr if the hook fails.
/// \note You can unhook the function by calling this function with \p callback set to the backup
/// set by previous call.
/// \note LSPlt will backup the hook memory region and restore it when the hook is restored
/// to its original function pointer so that there won't be dirty pages.
/// LSPlt will do hooks on a copied memory region so that the original memory region will not be
/// modified. You can invalidate this behaviour and hook the original memory region by calling
/// #InvalidateBackup().
/// \see #CommitHook()
/// \see #InvalidateBackup()
[[maybe_unused, gnu::visibility("default")]] bool RegisterHook(ino_t inode, std::string_view symbol,
                                                               void *callback, void **backup);

/// \brief Commit all registered hooks.
/// \return Whether all hooks are successfully committed. If any of the hooks fail to commit,
/// the result is false.
/// \note This function is thread-safe.
/// \note The return value indicates whether all hooks are successfully committed. You can
/// determine which hook fails by checking the backup function pointer of #RegisterHook().
/// \see #RegisterHook()
[[maybe_unused, gnu::visibility("default")]] bool CommitHook();

/// \brief Invalidate backup memory regions
/// Normally LSPlt will backup the hooked memory region and do hook on a copied anonymous memory
/// region, and restore the original memory region when the hook is unregistered
/// (when the callback of #RegisterHook() is the original function). This function will restore
/// the backup memory region and do all existing hooks on the original memory region.
/// \return Whether all hooks are successfully invalidated. If any of the hooks fail to invalidate,
/// the result is false.
/// \note This function is thread-safe.
/// \note This will be automatically called when the library is unloaded.
/// \see #RegisterHook()
[[maybe_unused, gnu::visibility("default")]] bool InvalidateBackup();
}  // namespace v1
}  // namespace lsplt
