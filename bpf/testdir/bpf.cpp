// don't include in string to compile with BCC:
#include <helpers.h> // BPF stuff
#include <linux/err.h>

#define EDITOR_ONLY // stuff only defined for editing this file and having autocomplete, not relevant for the actual BPF program

#define PATH_DEPTH 10
#define FILENAME_BUFSIZE 64

#define FILTER_BY_PID 1
#define INCLUDE_CHILD_PROCESSES 1
#define FILTER_BY_UID 1
#define FILTER_BY_GID 1
#define FILTER_BY_PATH 1
#define PATHFILTER_PATHPART_LENGTH 16 // number of bytes / characters allocated per path part (determined by longest path part)
#define PATHFILTER_MAX_PARTS_PER_PATH 16 // maximum number of parts per path; excluding "/" parts as they are ignored; including a "\0" as last part
#define PATHFILTER_PATHES 3

#define LOG_DELETES 1
#define LOG_READS 1
#define LOG_WRITES 1

#define RB_PAGES_EVENT_MAIN 8
#define RB_PAGES_EVENT_PATH 8

// compile with BCC the code below:
//------BPF_START------
#include <linux/version.h>

#define randomized_struct_fields_start  struct {
#define randomized_struct_fields_end    };

#include <asm/ptrace.h> // pt_regs
// Kernel 6.x+ has static_assert(sizeof(struct filename) % 64 == 0) in linux/fs.h.
// With RANDSTRUCT disabled (our BPF env) the struct is 40 bytes and the assert fires.
// Pull in build_bug.h first (it defines __static_assert), then suppress it so the
// include-guard prevents linux/fs.h from redefining it.
#include <linux/build_bug.h>
#undef __static_assert
#define __static_assert(expr, ...) /* suppress kernel layout assertions in BPF context */
#include <linux/fs.h> // file
#undef __static_assert
#include <linux/path.h> // path
#include <linux/mount.h> // mount
#include <linux/uio.h> // iov_iter
#include <linux/mm_types.h> // vm_area_struct (vm_fault is only forward-declared here)

// linux/mm.h has the full vm_fault definition but is too large for BPF context.
// mm_types.h only forward-declares it (struct vm_fault;), so we provide the layout
// ourselves. Fields match kernel 7.x x86_64 — vma/gfp_mask/pgoff/address/flags come
// from the leading anonymous const struct followed by enum fault_flag flags.
struct vm_fault {
    struct vm_area_struct *vma; // offset  0
    u32 gfp_mask;               // offset  8
    u32 _pad0;                  // offset 12 (padding: pgoff_t needs 8-byte alignment)
    u64 pgoff;                  // offset 16
    u64 address;                // offset 24
    u64 real_address;           // offset 32
    u32 flags;                  // offset 40
};

// readahead_control from linux/pagemap.h (not included: it pulls linux/mm.h which
// redefines vm_fault). Layout verified from pagemap.h on kernel 6.18.21 x86_64.
struct readahead_control {
    struct file *file;             // offset  0
    struct address_space *mapping; // offset  8
    struct file_ra_state *ra;      // offset 16
    u64 _index;                    // offset 24 (pgoff_t = unsigned long)
    u32 _nr_pages;                 // offset 32
    u32 _batch_count;              // offset 36
    u8  dropbehind;                // offset 40
    u8  _workingset;               // offset 41
    u8  _pad[6];                   // offset 42-47 (alignment padding)
    u64 _pflags;                   // offset 48
};

#include <linux/sched.h>

// from fs/internal.h
struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

#if FILTER_BY_PID
// Set of the PIDs to log.
BPF_HASH(log_pids, pid_t, u8);
#endif

#if FILTER_BY_UID
BPF_HASH(log_uids, u32, u8);
#endif

#if FILTER_BY_GID
BPF_HASH(log_gids, u32, u8);
#endif

#if FILTER_BY_PATH
struct path_part_t
{
    char str[PATHFILTER_PATHPART_LENGTH];
};

BPF_ARRAY(log_paths, struct path_part_t, PATHFILTER_MAX_PARTS_PER_PATH * PATHFILTER_PATHES);
#endif

// Since file* cannot be used directly (as it may be reused often), we have to generate a unique id for each open / opened handle.

BPF_ARRAY(global_handle_uid, u64, 1);
BPF_HASH(opened, struct file*, u64);

// Same has to be done for file inodes. Further we keep track of open handle count for the inodes. Both in closing a handle and unlinking the inode, handle count and if the inode is fully unlinked is checked and the inode is removed from the map if both are true.
struct saved_inode_t
{
    u64 inode_uid;
    u32 opened_handles;
};

BPF_ARRAY(global_inode_uid, u64, 1);
BPF_HASH(inodes, unsigned long, struct saved_inode_t);

// This struct is transmitted multiple times per open for each segment of the path (from back to front).
struct event_transmit_path_t
{
    u64 uid;
    u8 event_type;
    u8 path_type;
    u8 final; // last path for the event
    u8 last; // last path fragment for the event
    char filename[FILENAME_BUFSIZE];
};

BPF_RINGBUF_OUTPUT(event_transmit_path, RB_PAGES_EVENT_PATH);

enum event_type_t : u8
{
    TYPE_OPEN = 'O',
    TYPE_CLOSE = 'C',
    TYPE_READ = 'R',
    TYPE_MMAP_READ = 'M', // filemap_fault path (mmap page fault); ra_size used as size
    TYPE_WRITE = 'W',
    TYPE_DELETE = 'U'
};

// This struct is submitted for every event.
struct event_main_t
{
    u64 time_start;
    u64 time_end;
    u32 pid;
    u64 utime_start;
    u64 utime_end;
    u64 stime_start;
    u64 stime_end;
    u64 inode_uid;
    u8 type;
    s64 result;
    u64 handle_uid;
    u64 offset;
    u64 size;
    u64 flags;
};

BPF_RINGBUF_OUTPUT(event_main, RB_PAGES_EVENT_MAIN);

static void PrepareMainEvent(struct event_main_t* event)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->time_start = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->utime_start = task->utime;
    event->stime_start = task->stime;
}

static void SetEventFileStuff(struct event_main_t* event, struct file* file)
{
    int zero = 0;
    unsigned long inode = file->f_inode->i_ino;
    struct saved_inode_t* saved_inode = inodes.lookup(&inode);

    if (saved_inode == NULL)
    {
        struct saved_inode_t new_saved_inode = {};
        u64* p_global_inode_uid = global_inode_uid.lookup(&zero);
        if (p_global_inode_uid != NULL) // will not fail, BPF wants the check though
            event->inode_uid = new_saved_inode.inode_uid = ++(*p_global_inode_uid);
        new_saved_inode.opened_handles = 1; // new inode also means new handle
        inodes.insert(&inode, &new_saved_inode);
    }
    else
        event->inode_uid = saved_inode->inode_uid;

    u64* saved_handle = opened.lookup(&file);
    if (saved_handle == NULL)
    { // new handle, generate a new uid, check inode
        u64 new_saved_handle;

        u64* p_global_handle_uid = global_handle_uid.lookup(&zero);
        if (p_global_handle_uid != NULL) // will not fail, BPF wants the check though
            event->handle_uid = new_saved_handle = ++(*p_global_handle_uid);

        opened.insert(&file, &new_saved_handle);

        if (saved_inode != NULL)
            saved_inode->opened_handles++;
    }
    else // handle known, just take saved information
        event->handle_uid = *saved_handle;

    event->offset = file->f_pos;
    event->flags = file->f_flags;
}

static void FinalizeAndSubmitMainEvent(struct pt_regs* ctx, struct event_main_t* event)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->time_end = bpf_ktime_get_ns();
    event->utime_end = task->utime;
    event->stime_end = task->stime;

    event_main.ringbuf_output(event, sizeof(*event), 0);
}

static void OutputDentry(struct pt_regs* ctx, struct event_transmit_path_t* path_data, struct dentry* entry, bool finalize)
{
    path_data->last = 0;

    #pragma unroll (PATH_DEPTH)
    for (int i = 0; i < PATH_DEPTH; i++)
    {
        if (!entry) break;

        int copied_size = bpf_probe_read_kernel_str(path_data->filename, sizeof(path_data->filename), entry->d_name.name);

        if (copied_size > 0)
        {
            event_transmit_path.ringbuf_output(path_data, sizeof(*path_data), 0);
            entry = entry->d_parent;
        }
        else
        {
            entry = NULL;
        }
    }

    if (finalize)
    {
        path_data->last = 1; // communicate end
        event_transmit_path.ringbuf_output(path_data, sizeof(*path_data), 0);
    }
}

static void OutputFilePaths(struct pt_regs* ctx, struct event_transmit_path_t* path_data, struct file* fp)
{
    path_data->final = 0;
    path_data->path_type = 'F';
    OutputDentry(ctx, path_data, fp->f_path.dentry, true);

    path_data->path_type = 'M';
    OutputDentry(ctx, path_data, fp->f_path.mnt->mnt_root, true);

    path_data->final = 1;
    path_data->path_type = 'S';
    OutputDentry(ctx, path_data, fp->f_path.mnt->mnt_sb->s_root, true); // not sure what the functional difference is between this line and the one above
}

static bool CheckToLog()
{
#if FILTER_BY_PID
    pid_t pid = (bpf_get_current_pid_tgid() >> 32);

    if (log_pids.lookup(&pid) == NULL)
        return false;
#endif

#if FILTER_BY_UID
    u32 uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF);

    if (log_uids.lookup(&uid) == NULL)
        return false;
#endif

#if FILTER_BY_GID
    u32 gid = (bpf_get_current_uid_gid() >> 32);

    if (log_gids.lookup(&gid) == NULL)
        return false;
#endif

    return true;
}

struct save_t
{
    union
    {
        const struct path* path; // open
        struct
        { // close
            unsigned long inode; // if -1, handle is not actually freed as there are other references to it
            bool unlinked_inode;
        };
    };

    struct file *fp;
    struct event_main_t event;
};

BPF_HASH(save, u64, struct save_t);

// Files seen via vfs_read; used to suppress filemap_fault double-counting.
BPF_HASH(vfs_read_files, struct file*, u8);

// Readahead-event state: saved at page_cache_ra_order entry, finalized at return.
struct save_ra_t {
    struct event_main_t event;
    struct file_ra_state *ra;
};
BPF_HASH(save_ra, u64, struct save_ra_t);

// internal function handling most logic for open kprobes to reduce redundancy
static void do_open(bool insert, struct file* fp)
{
    if (!CheckToLog())
        return;

    u64 id = bpf_get_current_pid_tgid();
    struct save_t saved = {};
    saved.fp = fp;
    PrepareMainEvent(&saved.event);
    saved.event.type = TYPE_OPEN;
    if (insert)
        save.insert(&id, &saved);
    else
        save.update(&id, &saved);
}

// internal function handling most logic for open kretprobes to reduce redundancy
// if fp is NULL, the FP saved in open is used
static void do_ret_open(struct pt_regs *ctx, s64 result, struct file* fp)
{
    u64 id = bpf_get_current_pid_tgid();
    struct save_t* saved = save.lookup(&id);

    if (saved != NULL)
    {
        if (fp != NULL)
            saved->fp = fp;

        if (saved->fp && !IS_ERR_VALUE(saved->fp)) // no error opening the file / valid file struct pointer
            SetEventFileStuff(&saved->event, saved->fp); // will not be executed on error -> therefor won't save handle
        else // error; todo: maybe save flags / filename from original call
            saved->fp = NULL;

        struct event_transmit_path_t path_data = {};
        path_data.event_type = TYPE_OPEN;
        path_data.uid = saved->event.handle_uid;

        saved->event.result = result;
        OutputFilePaths(ctx, &path_data, saved->fp);
        FinalizeAndSubmitMainEvent(ctx, &saved->event);
        save.delete(&id);
    }
}

// used for do_filp_open, do_file_open_root
// we need those to catch the cases that circumvent vfs_open
// however, a pointer to the file structure is returned instead of being passed as an argument
int open_without_file(struct pt_regs *ctx, int dfd, struct filename *pathname, const struct open_flags *op)
{
    do_open(true, NULL);
    return 0;
}

int ret_open_returning_file(struct pt_regs *ctx)
{
    struct file* fp = (struct file*)PT_REGS_RC(ctx);
    do_ret_open(ctx, IS_ERR_VALUE(fp) ? (s64)fp : 0, fp);
    return 0;
}

// used for vfs_open and the filesystem specific open functions
int open_with_file(struct pt_regs *ctx, void *unused, struct file *file)
{
    do_open(false, file);
    return 0;
    // we use update here since there might already be an entry if vfs_open is called through do_filp_open or do_file_open_root
    // then we basically only log vfs_open and drop do_filp_open / do_file_open_root as that is not needed anymore
    // because only one open log is needed and the other two functions are attached to catch any atomic_open case which on success skips vfs_open
}

int ret_open_without_file(struct pt_regs *ctx)
{
    do_ret_open(ctx, PT_REGS_RC(ctx), NULL);
    return 0;
}

int kprobe__filp_close(struct pt_regs *ctx, struct file *file)
{
    if (!CheckToLog())
        return 0;

    u64* saved_handle = opened.lookup(&file);

    if (saved_handle != NULL)
    {
        u64 id = bpf_get_current_pid_tgid();
        struct save_t saved = {};
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
        unsigned long c = file->f_ref.refcnt.counter;
        unsigned long count = c >= FILE_REF_RELEASED ? 0 : c + 1;
        if (count <= 1)
#else
        if (file->f_count.counter <= 1)
#endif
        {
            saved.inode = file->f_inode->i_ino;
            saved.unlinked_inode = (file->f_inode->i_nlink == 0);
        }
        else
            saved.inode = (unsigned long)-1;
        saved.fp = file;
        PrepareMainEvent(&saved.event);
        SetEventFileStuff(&saved.event, file);
        saved.event.type = TYPE_CLOSE;
        save.insert(&id, &saved);
    }

    return 0;
}

int kretprobe__filp_close(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct save_t* saved = save.lookup(&id);

    if (saved != NULL)
    {
        saved->event.result = PT_REGS_RC(ctx);

        if (saved->event.result == 0 && saved->inode != (unsigned long)-1)
        {
            opened.delete(&saved->fp);
            struct saved_inode_t* saved_inode = inodes.lookup(&saved->inode);

            if (saved_inode != NULL) // should always be the case
            {
                if (--saved_inode->opened_handles == 0 && saved->unlinked_inode)
                    inodes.delete(&saved->inode);
            }
        }

        FinalizeAndSubmitMainEvent(ctx, &saved->event);
        save.delete(&id);
    }

    return 0;
}

BPF_HASH(save_delete, u64, unsigned long);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
int kprobe__vfs_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
#else
int kprobe__vfs_unlink(struct pt_regs *ctx, struct user_namespace *mnt_userns, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
#endif
{
    u64 id = bpf_get_current_pid_tgid();
    unsigned long inode = dentry->d_inode->i_ino;
    struct saved_inode_t* saved_inode = NULL;

    if (dentry->d_inode->i_nlink <= 1)
    { // unlink potentially deletes file
        saved_inode = inodes.lookup(&inode);

        if (saved_inode != NULL && saved_inode->opened_handles == 0) // also it's one of "our" inodes that have no handles anymore, so we have to delete it, if unlink is successful
            save_delete.insert(&id, &inode);
    }

#if LOG_DELETES
    if (CheckToLog())
    {
        if (saved_inode == NULL)
            saved_inode = inodes.lookup(&inode);

        struct event_transmit_path_t path_data = {};
        path_data.event_type = TYPE_DELETE;
        path_data.last = 0;
        struct save_t saved = {};
        PrepareMainEvent(&saved.event);
        saved.event.type = TYPE_DELETE;

        if (saved_inode != NULL)
            path_data.uid = saved.event.inode_uid = saved_inode->inode_uid;
        else
            path_data.uid = saved.event.inode_uid = (u64)-inode;

        path_data.final = 0;
        path_data.path_type = 'F';
        OutputDentry(ctx, &path_data, dentry, true);
        path_data.final = 1;
        path_data.path_type = 'S';
        OutputDentry(ctx, &path_data, dentry->d_sb->s_root, true);

        save.insert(&id, &saved);
    }
#endif

    return 0;
}

int kretprobe__vfs_unlink(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    unsigned long* saved_inode = save_delete.lookup(&id);

    if (saved_inode != NULL)
    {
        if (PT_REGS_RC(ctx) == 0) // unlink succeeded
            inodes.delete(saved_inode);

        save_delete.delete(&id);
    }

#if LOG_DELETES
    struct save_t* saved = save.lookup(&id);

    if (saved != NULL)
    {
        saved->event.result = PT_REGS_RC(ctx);
        FinalizeAndSubmitMainEvent(ctx, &saved->event);
        save.delete(&id);
    }
#endif

    return 0;
}

static int do_readwrite(struct file* file, size_t size, loff_t* pos, u8 type)
{
    if (!CheckToLog())
        return 0;

    u64* saved_handle = opened.lookup(&file);

    if (saved_handle != NULL)
    {
        struct save_t saved = {};
        PrepareMainEvent(&saved.event);
        SetEventFileStuff(&saved.event, file);
        saved.event.type = type;
        saved.event.size = size;
        saved.event.offset = *pos;
        saved.fp = file;

        if (type == TYPE_READ) {
            u8 one = 1;
            vfs_read_files.insert(&file, &one);
        }

        u64 id = bpf_get_current_pid_tgid();
        save.insert(&id, &saved);
    }

    return 0;
}

int probe__vfs_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    return do_readwrite(file, count, pos, TYPE_WRITE);
}

int probe__vfs_read(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    return do_readwrite(file, count, pos, TYPE_READ);
}

int probe__do_iter_write(struct pt_regs *ctx, struct file *file, struct iov_iter *iter, loff_t *pos, rwf_t flags)
{ // covers vfs_iter_write, vfs_writev
    return do_readwrite(file, iter->count, pos, TYPE_WRITE);
}

int probe__do_iter_read(struct pt_regs *ctx, struct file *file, struct iov_iter *iter, loff_t *pos, rwf_t flags)
{ // covers vfs_iter_read, vfs_readv
    return do_readwrite(file, iter->count, pos, TYPE_READ);
}

int probe__do_iter_readv_writev(struct pt_regs *ctx, struct file *file, struct iov_iter *iter, loff_t *pos, int type, rwf_t flags)
{ // for kernel 6+ instead of do_iter_read / do_iter_write
    if (LOG_READS && type == READ)
        return do_readwrite(file, iter->count, pos, TYPE_READ);
    else if (LOG_WRITES && type == WRITE)
        return do_readwrite(file, iter->count, pos, TYPE_WRITE);
}

int probe__vfs_iocb_iter_write(struct pt_regs *ctx, struct file *file, struct kiocb *iocb, struct iov_iter *iter)
{
    return do_readwrite(file, iter->count, &iocb->ki_pos, TYPE_WRITE);
}

int probe__vfs_iocb_iter_read(struct pt_regs *ctx, struct file *file, struct kiocb *iocb, struct iov_iter *iter)
{
    return do_readwrite(file, iter->count, &iocb->ki_pos, TYPE_READ);
}

// Captures mmap-triggered reads that bypass vfs_read via the page-fault path.
// filemap_fault() is called when a process accesses a mmap'd page not yet in cache.
// FAULT_FLAG_WRITE (0x01) guards skip COW/write faults — only read faults are logged.
#define FAULT_FLAG_WRITE_BPF 0x01
int probe__filemap_fault(struct pt_regs *ctx, struct vm_fault *vmf)
{
    if (!CheckToLog())
        return 0;

    unsigned int fault_flags;
    bpf_probe_read(&fault_flags, sizeof(fault_flags), &vmf->flags);
    if (fault_flags & FAULT_FLAG_WRITE_BPF)
        return 0;

    struct vm_area_struct *vma;
    bpf_probe_read(&vma, sizeof(vma), &vmf->vma);
    if (!vma)
        return 0;

    struct file *file;
    bpf_probe_read(&file, sizeof(file), &vma->vm_file);
    if (!file)
        return 0;

    // Only log files opened by a tracked process (same guard as do_readwrite)
    if (opened.lookup(&file) == NULL)
        return 0;

    // Skip files already tracked via vfs_read to avoid double-counting.
    // Those files are fully covered by the vfs_read probe.
    if (vfs_read_files.lookup(&file) != NULL)
        return 0;

    pgoff_t pgoff;
    bpf_probe_read(&pgoff, sizeof(pgoff), &vmf->pgoff);
    loff_t pos = (loff_t)pgoff << PAGE_SHIFT;
    return do_readwrite(file, PAGE_SIZE, &pos, TYPE_MMAP_READ);
}

int ret_filemap_fault(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct save_t* saved = save.lookup(&id);
    if (saved != NULL)
    {
        // vm_fault_t is a bitmask; VM_FAULT_OOM (0x2) and VM_FAULT_SIGBUS (0x4) are errors
        u32 rc = (u32)(u64)PT_REGS_RC(ctx);
        if (rc & 0x0006) {
            saved->event.result = -1;
        } else {
            // ra_size is the readahead window (pages) populated by this fault.
            // Use it as the event size so the full batch I/O is accounted for.
            // Only emit if the file wasn't already tracked via vfs_read (to
            // avoid double-counting files accessed through both paths).
            struct file *fp = saved->fp;
            unsigned int ra_size = 0;
            bpf_probe_read(&ra_size, sizeof(ra_size), &fp->f_ra.size);
            u64 actual = ra_size > 0 ? (u64)ra_size << PAGE_SHIFT : PAGE_SIZE;
            saved->event.size = actual;
            saved->event.result = (s64)actual;
        }
        FinalizeAndSubmitMainEvent(ctx, &saved->event);
        save.delete(&id);
    }
    return 0;
}

// Captures readahead-driven reads for both mmap and vfs_read paths.
// Both page_cache_sync_ra and page_cache_async_ra route through this function
// once per readahead batch. ra->size at return is the actual batch page count.
int probe__page_cache_ra_order(struct pt_regs *ctx,
                                struct readahead_control *ractl,
                                struct file_ra_state *ra,
                                unsigned int new_order)
{
    if (!CheckToLog()) return 0;
    if (!ra) return 0;

    struct file *file;
    bpf_probe_read(&file, sizeof(file), &ractl->file);
    if (!file) return 0;
    if (opened.lookup(&file) == NULL) return 0;
    // Skip files tracked via vfs_read — readahead is already accounted for there.
    if (vfs_read_files.lookup(&file) != NULL) return 0;

    u64 index;
    bpf_probe_read(&index, sizeof(index), &ractl->_index);

    struct save_ra_t s = {};
    PrepareMainEvent(&s.event);
    SetEventFileStuff(&s.event, file);
    s.event.type = TYPE_READ;
    s.event.offset = (loff_t)index << PAGE_SHIFT;
    s.ra = ra;

    u64 id = bpf_get_current_pid_tgid();
    save_ra.insert(&id, &s);
    return 0;
}

int ret_page_cache_ra_order(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct save_ra_t *s = save_ra.lookup(&id);
    if (!s) return 0;

    unsigned int ra_size;
    bpf_probe_read(&ra_size, sizeof(ra_size), &s->ra->size);

    if (ra_size > 0) {
        s->event.size = (u64)ra_size << PAGE_SHIFT;
        s->event.result = (s64)s->event.size;
        FinalizeAndSubmitMainEvent(ctx, &s->event);
    }

    save_ra.delete(&id);
    return 0;
}

int retprobe__readwrites(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct save_t* saved = save.lookup(&id);

    if (saved != NULL)
    {
        saved->event.result = PT_REGS_RC(ctx);
        FinalizeAndSubmitMainEvent(ctx, &saved->event);
        save.delete(&id);
    }

    return 0;
}

#if FILTER_BY_PID
TRACEPOINT_PROBE(sched, sched_process_exit)
{
    // args is defined as seen /sys/kernel/debug/tracing/events/sched/sched_process_exit/format
    #ifdef EDITOR_ONLY
    struct
    {
        u16 common_type;
        u8 common_flags;
        u8 common_preempt_count;
        s32 common_pid;

        char comm[16];
        pid_t pid;
        int prio;
    } *real_args;
    #define args real_args
    #endif

    pid_t pid = args->pid;
    log_pids.delete(&pid);

    #ifdef EDITOR_ONLY
    #undef args
    #endif
    return 0;
}

#if INCLUDE_CHILD_PROCESSES
TRACEPOINT_PROBE(sched, sched_process_fork)
{
    // args is defined as seen /sys/kernel/debug/tracing/events/sched/sched_process_fork/format
    #ifdef EDITOR_ONLY
    struct
    {
        u16 common_type;
        u8 common_flags;
        u8 common_preempt_count;
        s32 common_pid;

        char parent_comm[16];
        pid_t parent_pid;
        char child_comm[16];
        pid_t child_pid;
    } *real_args;
    #define args real_args
    #endif

    pid_t pid = args->parent_pid;

    if (log_pids.lookup(&pid) != NULL)
    {
        u8 one = 1;
        pid = args->child_pid;
        log_pids.insert(&pid, &one);
    }

    #ifdef EDITOR_ONLY
    #undef args
    #endif
    return 0;
}
#endif
#endif

//------BPF_END------
