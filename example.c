#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

/*
 * Fork a child process and set it up for tracing.
 * Replaces the child's image with the target program.
 */
pid_t run_target(char* const argv[])
{
    pid_t pid = fork();
    if (pid > 0) {
        return pid;
    } else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        execv(argv[0], argv);
        exit(1);
    } else {
        perror("fork");
        exit(1);
    }
    return 0;
}

void* get_elf_content(const char* sym_name, const char* file_name)
{
    // Open ELF file for reading
    int elf_fd = open(file_name, O_RDONLY);
    if (elf_fd < 0) {
        perror("failed to open file");
        return NULL;
    }

    // Get file size
    struct stat elf_stats;
    int ret = fstat(elf_fd, &elf_stats);
    if (ret < 0) {
        perror("fstat failed");
        close(elf_fd);
        return NULL;
    }
    long file_size = elf_stats.st_size;

    // Allocate memory for the file content
    void* file_content = malloc(file_size);
    if (!file_content) {
        perror("malloc failed");
        close(elf_fd);
        return NULL;
    }

    // Read ELF file content into memory
    ret = read(elf_fd, file_content, file_size);
    if (ret < file_size) {
        perror("read failed or incomplete");
        free(file_content);
        close(elf_fd);
        return NULL;
    }
    close(elf_fd);

    return file_content;
}

unsigned long parse_elf(const char* target_sym, void* file_contents)
{
    // --- PHASE A: FIND SYMBOL ADDRESS ---

    // 1. Cast `file_contents` to an ELF header pointer
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)file_contents;

    // 2. Find the Section Header Table
    Elf64_Shdr* section_headers = (Elf64_Shdr*)((char*)file_contents + elf_header->e_shoff);

    // 3. Iterate over the section headers to find the Symbol Table and String Table
    unsigned long symbol_table_offset = 0;
    unsigned long symbol_table_size = 0;
    unsigned long string_table_offset = 0;

    for (int i = 0; i < elf_header->e_shnum; i++) {
        if (section_headers[i].sh_type == SHT_SYMTAB) {
            symbol_table_offset = section_headers[i].sh_offset;
            symbol_table_size = section_headers[i].sh_size;

            int string_table_index = section_headers[i].sh_link;
            string_table_offset = section_headers[string_table_index].sh_offset;
            break;
        }
    }

    // 4. Calculate symbol count (Fixed from pointer to int)
    int num_symbols = symbol_table_size / sizeof(Elf64_Sym);

    // Cast symtable into array
    Elf64_Sym* sym_table = (Elf64_Sym*)((char*)file_contents + symbol_table_offset);

    // 5. Iterate through all symbols
    for(int i = 0; i < num_symbols; i++) {

        // Get the symbol's name from the String Table
        const char* sym_name = (const char*)file_contents + string_table_offset + sym_table[i].st_name;

        // Compare with the target symbol
        if (strcmp(sym_name, target_sym) == 0) {
            // Fixed variable name to match your array (sym_table)
            printf("PRF:: symbol address is 0x%lx\n", sym_table[i].st_value);
            return sym_table[i].st_value;
        }
    }

    // Fixed: Moved outside the loop! Only return 0 if the whole loop finishes without a match.
    return 0;
}

/*
 * Main debugger tracing loop.
 */
void run_tracer(pid_t child_pid, unsigned long addr, int nr_params)
{
    int wait_status;
    struct user_regs_struct regs;
    int func_call_ctr = 0; ///counter for how many times the func will be called
    int rec_depth = 0;
    int depth_capacity = 64; ///starting array size

    unsigned long* return_address_stack = (unsigned long*)malloc(depth_capacity * sizeof(unsigned long));
    long* saved_return_instructions = (long*)malloc(depth_capacity * sizeof(long));
    long target_original_instruction;

    wait(&wait_status); /// Wait for the child to stop right after fork/execv

    ///we read first 8 bytes from target
    target_original_instruction = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);

    ///we check if fisr byte is 0X55
    if ((target_original_instruction & 0xFF) == 0x55) {
        printf("PRF:: This function starts by pushing rbp\n");
    }

    /// Main Tracing Loop
    while (WIFSTOPPED(wait_status)) {

        ///we save the upper 7 bytes and change first to 0xcc
        long break_point = (target_original_instruction & ~0xFFL) | 0xCC;

        /// we put break point in the target func addr
        ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)break_point);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);

        ///we wiat the prog to arrive to breakp
        wait(&wait_status);

        ///if it finishes we go out!
        if (WIFEXITED(wait_status)) {
            break;
        }

        ///else we update regs and cpu to see where it stopped
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

        ///calc real address
        unsigned long stopped_address = regs.rip - 1;

        /// --- PATH A: FUNCTION ENTRY ---
        /// If the program stopped exactly at our target function
        if (stopped_address == addr) {

            /// expand stack if rec is deep
            if (rec_depth >= depth_capacity) {
                depth_capacity *= 2;
                return_address_stack = (unsigned long*)realloc(return_address_stack, depth_capacity * sizeof(unsigned long));
                saved_return_instructions = (long*)realloc(saved_return_instructions, depth_capacity * sizeof(long));
            }

            /// LOG ENTRY & PRINT
            rec_depth++;
            if (rec_depth == 1) {
                func_call_ctr++;
                printf("PRF:: run #%d called with (", func_call_ctr);
            } else {
                printf("    PRF:: entered recursive call with (");
            }

            /// Print regs based on nr_params
            switch (nr_params) {
                case 0:
                    break;
                case 1:
                    printf("%lld", (long long)regs.rdi);
                    break;
                case 2:
                    printf("%lld, %lld", (long long)regs.rdi, (long long)regs.rsi);
                    break;
                case 3:
                    printf("%lld, %lld, %lld", (long long)regs.rdi, (long long)regs.rsi, (long long)regs.rdx);
                    break;
                case 4:
                    printf("%lld, %lld, %lld, %lld", (long long)regs.rdi, (long long)regs.rsi, (long long)regs.rdx, (long long)regs.rcx);
                    break;
                case 5:
                    printf("%lld, %lld, %lld, %lld, %lld", (long long)regs.rdi, (long long)regs.rsi, (long long)regs.rdx, (long long)regs.rcx, (long long)regs.r8);
                    break;
                case 6:
                    printf("%lld, %lld, %lld, %lld, %lld, %lld", (long long)regs.rdi, (long long)regs.rsi, (long long)regs.rdx, (long long)regs.rcx, (long long)regs.r8, (long long)regs.r9);
                    break;
                default:
                    break;
            }

            if (rec_depth == 1) {
                printf("):\n");
            } else {
                printf(")\n");
            }

            /// 1. Read the return ticket from the top of the Stack (RSP)
            unsigned long ret_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)regs.rsp, NULL);
            return_address_stack[rec_depth - 1] = ret_addr;

            /// check: does an outer, still-waiting frame already have a break_point sitting
            /// at this exact address? (happens when the caller, like rec_bar, always calls us
            /// from the same instruction, so different recursion levels share one exit door)
            /// if so we must NOT peek it now (byte there is already 0xcc from the outer plant,
            /// we'd end up saving a corrupted "original"), and must NOT plant again either
            int already_has_break_point = 0;
            long reused_original_instruction = 0;
            for (int k = 0; k < rec_depth - 1; k++) {
                if (return_address_stack[k] == ret_addr) {
                    already_has_break_point = 1;
                    reused_original_instruction = saved_return_instructions[k];
                    break;
                }
            }

            if (already_has_break_point) {
                /// 2. just reuse the real original instruction the outer frame already grabbed
                saved_return_instructions[rec_depth - 1] = reused_original_instruction;
                /// 3. break_point already planted by that outer frame, nothing more to do here
            } else {
                /// 2. Backup the real code at that exit door
                long ret_original = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)ret_addr, NULL);
                saved_return_instructions[rec_depth - 1] = ret_original;

                /// 3. Plant our 0xCC break_point at the exit door
                long ret_break_point = (ret_original & ~0xFFL) | 0xCC;
                ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_addr, (void*)ret_break_point);
            }

            /// 1. Remove the entry trap temporarily so it doesn't crash
            ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)target_original_instruction);

            /// 2. Move the RIP pointer back 1 byte to read the real instruction
            regs.rip = stopped_address;
            ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

            /// 3. Let it execute exactly ONE instruction, then pause it again
            ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
            wait(&wait_status);
        }
        /// --- PATH B: FUNCTION RETURN ---
        /// If the program stopped at the return address we saved earlier
        else if (rec_depth > 0 && stopped_address == return_address_stack[rec_depth - 1]) {

            /// check: does a shallower (still-waiting) frame ALSO return through this exact
            /// same exit door? (same shared-call-site thing as on entry) if so we can't just
            /// restore-and-forget - that frame still needs the break_point here later on
            int break_point_still_needed = 0;
            for (int k = 0; k < rec_depth - 1; k++) {
                if (return_address_stack[k] == stopped_address) {
                    break_point_still_needed = 1;
                    break;
                }
            }

            /// 2. If we are finishing the very first (outer) call, print the return value
            if (rec_depth == 1) {
                printf("  PRF:: call to function returned with %lld\n", (long long)regs.rax);
            }

            /// 3. We left the function, so decrease the recursion depth
            rec_depth--;

            /// 4. Move RIP back 1 byte to execute the real return instruction
            regs.rip = stopped_address;
            ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

            if (!break_point_still_needed) {
                /// 1. nobody else needs this break_point anymore, remove it for real
                ptrace(PTRACE_POKETEXT, child_pid, (void*)stopped_address, (void*)saved_return_instructions[rec_depth]);
            } else {
                /// 1. someone shallower still needs this break_point: restore it, step past
                ///    it ourselves, then plant it back so their break_point is there when they return
                ptrace(PTRACE_POKETEXT, child_pid, (void*)stopped_address, (void*)saved_return_instructions[rec_depth]);
                ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
                waitpid(child_pid, &wait_status, 0);
                long original_instruction = saved_return_instructions[rec_depth];
                long break_point_again = (original_instruction & ~0xFFL) | 0xCC;
                ptrace(PTRACE_POKETEXT, child_pid, (void*)stopped_address, (void*)break_point_again);
            }
        }
    }

    /// clean up memory
    free(return_address_stack);
    free(saved_return_instructions);
}

int main(int argc, char* const argv[])
{
    if (argc < 4) {
        printf("usage: <sym_name> <number of input params> <elf_path> "
               "[optional input params for elf file]\n");
        return 0;
    }

    const char* sym_name  = argv[1];
    int nr_params         = strtol(argv[2], NULL, 10);
    const char* file_name = argv[3];

    // Put file content into memory for parsing
    void* file_content = get_elf_content(sym_name, file_name);

    // Find the symbol address
    unsigned long addr = parse_elf(sym_name, file_content);

    // Free the allocated memory
    free(file_content);

    // If parse_elf returned 0, it wasn't found.
    // You MUST print "PRF:: symbol not found\n" and return 1.
    if (addr == 0) {
        printf("PRF:: symbol not found\n");
        return 1;
    }

    // Launch the target program
    pid_t child_pid = run_target(argv + 3);

    // Run the tracer
    run_tracer(child_pid, addr, nr_params);

    return 0; // Return 0 on success
}