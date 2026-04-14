#ifndef LOGFS_FILESYSTEM_HPP
#define LOGFS_FILESYSTEM_HPP

#include <fuse3/fuse_lowlevel.h>

#include <atomic>
#include <limits>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <vector>
#include <span>

#include <poll.h>
#include <unistd.h>

namespace LogFs
{
    struct Node
    {
        Node(int fd, ino_t ino) : fd(fd), ino(ino) {}
        ~Node();

        Node(const Node &) = delete;
        Node(Node &&) = delete;
        Node &operator=(const Node &) = delete;
        Node &operator=(Node &&) = delete;

        int fd;
        ino_t ino;
        std::atomic<uint64_t> lookup = 0;
    };

    class LogEntry
    {
    public:
        static LogEntry GetOpen(int pid, uint64_t inode, int flags);
        static LogEntry GetClose(int pid, uint64_t inode, uint64_t fh);
        static LogEntry GetRead(int pid, uint64_t inode, uint64_t fh, off_t off, size_t size);
        static LogEntry GetWrite(int pid, uint64_t inode, uint64_t fh, off_t off, size_t size);
        void end(int res);
        std::span<char> getBuf();
        bool unknownFh() const;
        
        static void InformNewNode(uint64_t inode, bool created);

        static constexpr auto SizeTimeSec    =  20; // maybe a '-' followed by up to 19 digits, a '.' and 3 digits
        static constexpr auto SizeTimeNsec   =   3; // 3 digits
        static constexpr auto SizeTime       =  SizeTimeSec + 1 + SizeTimeNsec; // maybe a '-' followed by up to 19 digits, a '.' and 3 digits
        static constexpr auto SizePid        =  11; // maybe a '-' followed by up to 10 digits
        static constexpr auto SizeInode      =  20; // up to 20 digits
        static constexpr auto SizeEvent      =   1; // 1 byte
        static constexpr auto SizeResult     =  11; // maybe a '-' followed by up to 10 digits
        static constexpr auto SizeFilehandle =  20; // maybe a '-' followed by up to 19 digits
        static constexpr auto SizeOffset     =  20; // maybe a '-' followed by up to 19 digits
        static constexpr auto SizeSize       =  20; // up to 20 digits
        static constexpr auto SizeFlags      =  10; // "0x" followed by 8 digits
        static constexpr auto SizePath       = 240; // up to 240 characters for now

        static constexpr auto OffRTimeStart = 0;
        static constexpr auto OffRTimeEnd   = OffRTimeStart + SizeTime       + 1;
        static constexpr auto OffPid        = OffRTimeEnd   + SizeTime       + 1;
        static constexpr auto OffUTimeStart = OffPid        + SizePid        + 1;
        static constexpr auto OffUTimeEnd   = OffUTimeStart + SizeTime       + 1;
        static constexpr auto OffSTimeStart = OffUTimeEnd   + SizeTime       + 1;
        static constexpr auto OffSTimeEnd   = OffSTimeStart + SizeTime       + 1;
        static constexpr auto OffInode      = OffSTimeEnd   + SizeTime       + 1;
        static constexpr auto OffEvent      = OffInode      + SizeInode      + 1;
        static constexpr auto OffResult     = OffEvent      + SizeEvent      + 1;
        static constexpr auto OffFilehandle = OffResult     + SizeResult     + 1;
        static constexpr auto OffOffset     = OffFilehandle + SizeFilehandle + 1;
        static constexpr auto OffSize       = OffOffset     + SizeOffset     + 1;
        static constexpr auto OffFlags      = OffSize       + SizeSize       + 1;
        static constexpr auto OffPath       = OffFlags      + SizeFlags      + 1;

        static constexpr auto SizeEntry = OffPath + SizePath + 1;

    private:
        void start(int pid, uint64_t ino, char evt, uint64_t fh);
        
        static void GetRTime(timespec *rTime);
        static void GetPidStatTimes(int pid, timespec *utime, timespec *stime);

        static std::unordered_map<uint64_t, uint64_t> Fhs;
        static std::shared_mutex MutexFhs;
        static std::atomic<int64_t> CurFh;
        static std::unordered_map<uint64_t, uint64_t> Inodes;
        static std::shared_mutex MutexInodes;
        static std::atomic<int64_t> CurInode;

        union
        {
            char buffer[SizeEntry];
            struct
            {
                timespec rTimeStart;
                timespec rTimeEnd;
                int pid;
                timespec uTimeStart;
                timespec uTimeEnd;
                timespec sTimeStart;
                timespec sTimeEnd;
                uint64_t inode;
                char event;
                int result;
                int64_t filehandle;
                uint64_t offset;
                uint64_t size;
                int flags;
            };
        };
    };

    struct FileSystem
    {
        struct PollMessage
        {
            fuse_pollhandle *ph;
            pollfd pfd;
        };

        Node &getNode(fuse_ino_t ino) const;
        Node *findChild(Node &parent, const char *name, struct stat *attr);
        
        int setupPollPipe();
        int killPollThread(bool notifyPollHandles = false);
        int poll(const PollMessage &ph) const;
        int writeLog(std::span<char> logData);

        std::unordered_map<ino_t, Node> nodes;
        std::shared_mutex nodesMutex;
        std::shared_mutex createMutex; /// @todo: this could happen on parent node base
        std::unique_ptr<Node> root = nullptr;
        int pollpipeFd = -1;
        int logFd = STDOUT_FILENO;
        
        static fuse_lowlevel_ops GetOps();

        static thread_local std::vector<char> Buffer;
        static int ProcFd;

        constexpr static bool DirectIo = true;
        constexpr static bool KeepCache = true;
        constexpr static double EntryTimeout = std::numeric_limits<double>::max(); // 0.0;
        constexpr static double AttrTimeout = std::numeric_limits<double>::max(); // 0.0;
    };

    inline FileSystem Fs;
    inline bool UseMonotonic = false;
}

#endif // guard
