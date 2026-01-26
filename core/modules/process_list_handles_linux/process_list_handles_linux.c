#include "syscall_helpers.h"
#include "beacon_helpers.h"

// Static buffer to hold output (1MB)
static char output[1024 * 1024];

// Entry point
char* go(char* args, int len) {
    output[0] = '\0';
    size_t current_len = 0;
    size_t max_len = sizeof(output);

    // Initialize parser
    datap parser;
    BeaconDataParse(&parser, args, len);

    int pid = BeaconDataInt(&parser);
    if (pid == 0) {
        // If PID is 0, it might be an error or actually PID 0 (which is kernel, but we treat 0 as potentially parse error if length matched)
        // Checking if parser length was enough?
        // BeaconDataInt checks length. if length < 4 returns 0.
        // Assuming PID > 0 for this module.
        // Or if we really want to support PID 0, we can check parser.length before.
    }
    
    // If PID is still 0/default or we want to sanity check
    if (pid < 0) {
         append_str(output, &current_len, max_len, "Error: Invalid PID");
         return output;
    }

    char pid_str[32];
    my_itoa(pid, pid_str);

    char fd_path[256];
    // Construct /proc/<pid>/fd
    size_t path_off = 0;
    fd_path[0] = '\0';
    append_str(fd_path, &path_off, sizeof(fd_path), "/proc/");
    append_str(fd_path, &path_off, sizeof(fd_path), pid_str);
    append_str(fd_path, &path_off, sizeof(fd_path), "/fd");

    // Open directory using syscall
    long fd = syscall3(SYS_open, (long)fd_path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) {
        append_str(output, &current_len, max_len, "Error: Failed to open ");
        append_str(output, &current_len, max_len, fd_path);
        return output;
    }

    append_str(output, &current_len, max_len, "Listing handles for PID ");
    append_str(output, &current_len, max_len, pid_str);
    append_str(output, &current_len, max_len, ":\n\n");

    char buf[1024];
    long nread;
    while (1) {
        nread = syscall3(SYS_getdents64, fd, (long)buf, sizeof(buf));
        if (nread == -1) {
             append_str(output, &current_len, max_len, "Error: getdents64 failed\n");
             break;
        }
        if (nread == 0) break;

        for (int bpos = 0; bpos < nread;) {
            struct linux_dirent64 *d = (struct linux_dirent64 *) (buf + bpos);
            
            // Skip . and ..
            if (!(d->d_name[0] == '.' && (d->d_name[1] == '\0' || (d->d_name[1] == '.' && d->d_name[2] == '\0')))) {
                
                char link_path[1024];
                size_t lp_off = 0;
                link_path[0] = '\0';
                append_str(link_path, &lp_off, sizeof(link_path), fd_path);
                append_str(link_path, &lp_off, sizeof(link_path), "/");
                append_str(link_path, &lp_off, sizeof(link_path), d->d_name);

                char target_path[4096];
                long link_res = syscall3(SYS_readlink, (long)link_path, (long)target_path, sizeof(target_path) - 1);
                
                if (link_res >= 0) {
                    target_path[link_res] = '\0';
                } else {
                     target_path[0] = '\0';
                     size_t tp_off = 0;
                     append_str(target_path, &tp_off, sizeof(target_path), "(unreachable)");
                }

                if (current_len + 100 + my_strlen(target_path) >= max_len) {
                     append_str(output, &current_len, max_len, "\n... Output truncated ...\n");
                     goto close_end;
                }

                append_str(output, &current_len, max_len, d->d_name);
                append_str(output, &current_len, max_len, " -> ");
                append_str(output, &current_len, max_len, target_path);
                append_str(output, &current_len, max_len, "\n");
            }

            bpos += d->d_reclen;
        }
    }

close_end:
    syscall1(SYS_close, fd);
    return output;
}
