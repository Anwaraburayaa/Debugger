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

    // TODO 4: Iterate through all symbols in the Symbol Table.
    //         Compare each symbol's name with `target_sym` using strcmp.
Elf64_sym* sym_ctr=symbol_table_size/sizeof(Elf64_Sym);
///we cast symtable into array
    Elf64_Sym* sym_table = (Elf64_Sym*)((char*)file_contents + symbol_table_offset);
for(int i=0;i<sym_ctr;i++){
// Get the symbol's name from the String Table
        const char* sym_name = (const char*)file_contents + string_table_offset + sym_table[i].st_name;

        // Compare with the target symbol
        if (strcmp(sym_name, target_sym) == 0) {
            // Return the symbol's address (st_value)
            printf("PRF:: symbol address is 0x%lx\n", symbols[i].st_value);
            return sym_table[i].st_value;
        }
     return 0;

    }
}





/*
 * Main debugger tracing loop.
 */
void run_tracer(pid_t child_pid, unsigned long addr, int nr_params)
{
    int wait_status;
    struct user_regs_struct regs;

    // Variables you will likely need to manage state:
    // int call_counter = 0;
    // int current_depth = 0; // To distinguish main calls from recursive calls
    // unsigned long original_data; // To store the byte you replace with 0xCC

    wait(&wait_status); // Wait for the child to stop right after fork/execv

    // --- PHASE B: CHECK PROLOGUE ---
    // TODO 6: Read the data at 'addr' using ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL).
    // TODO 7: Save this data (you will need to restore it later).
    // TODO 8: Extract the first byte. If it is 0x55 (push rbp), print:
    //         printf("PRF:: This function starts by pushing rbp\n");

    // TODO 9: Main Tracing Loop
    // while (WIFSTOPPED(wait_status)) {

        // --- PHASE C: TRACING PARAMETERS ---
        // TODO 10: Plant a Breakpoint at 'addr'. Overwrite the first byte with 0xCC
        //          using ptrace(PTRACE_POKETEXT...).

        // TODO 11: Continue execution: ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        // TODO 12: wait(&wait_status);

        // TODO 13: Check if child exited (if WIFEXITED(wait_status), break the loop).

        // We hit the function!
        // TODO 14: Get registers: ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

        // TODO 15: Determine if this is a new outer call or a recursive call.
        //          (Hint: You might need to track the return addresses on a stack
        //          or just track the depth).
        //          - If OUTER call (depth == 0): print "PRF:: run #%d called with (...):\n"
        //          - If RECURSIVE call (depth > 0): print "PRF::    entered recursive call with (...)\n"
        //          Use `nr_params` to know which registers to read (rdi, rsi, rdx, rcx, r8, r9).

        // TODO 16: Read the return address from the top of the stack (regs.rsp).
        //          Use ptrace(PTRACE_PEEKTEXT...) at regs.rsp to get the return address.

        // --- PHASE D PREPARATION: RESTORE AND SET RETURN BREAKPOINT ---
        // TODO 17: Restore the original byte at 'addr' so the function can actually run.
        // TODO 18: Decrement regs.rip by 1 (regs.rip--) and update registers:
        //          ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

        // TODO 19: Plant a Breakpoint (0xCC) at the *return address* you found in step 16.
        //          (Remember to save the original data at the return address first!)

        // TODO 20: Continue execution: ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        // TODO 21: wait(&wait_status);

        // We hit the return address!
        // TODO 22: Get registers again to catch the return value.
        // TODO 23: If this was returning from an OUTER call (depth goes back to 0),
        //          print the return value from RAX:
        //          printf("PRF::  call to function returned with %lld\n", regs.rax);

        // TODO 24: Restore the original data at the return address.
        // TODO 25: Decrement regs.rip by 1 and update registers (PTRACE_SETREGS).
    // }
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

    // --- TODO 26: CHECK IF SYMBOL WAS FOUND ---
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
