#include "debugger.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#define BREAKPOINT_PLACEMENT (0xFFFFFFFFFFFFFF00)
#define BRK (0xCC)

void static placeHookInCaller(pid_t child_pid, uint64_t rsp_address, uint64_t *inst_backup)
{
    uint64_t callee_address = ptrace(PTRACE_PEEKTEXT, child_pid, rsp_address, NULL);
    // printf("calle address: 0x%lx\n", callee_address);
    *inst_backup = ptrace(PTRACE_PEEKTEXT, child_pid, callee_address, NULL);
    ptrace(PTRACE_POKETEXT, child_pid, callee_address, (*inst_backup & BREAKPOINT_PLACEMENT) | BRK);
}

void static placeHookInFunction(pid_t child_pid, uint64_t function_addr, uint64_t *inst_backup)
{
    // printf("function address: 0x%lx\n", function_addr);
    *inst_backup = ptrace(PTRACE_PEEKTEXT, child_pid, function_addr, NULL);
    ptrace(PTRACE_POKETEXT, child_pid, function_addr, (*inst_backup & BREAKPOINT_PLACEMENT) | BRK);
}

void static placeHookInGotOffsetPtr(pid_t child_pid, uint64_t got_addr, uint64_t *inst_backup)
{
    uint64_t function_addr = ptrace(PTRACE_PEEKTEXT, child_pid, got_addr, NULL);
    // printf("got function address: 0x%lx\n", function_addr);
    *inst_backup = ptrace(PTRACE_PEEKTEXT, child_pid, function_addr, NULL);
    ptrace(PTRACE_POKETEXT, child_pid, function_addr, (*inst_backup & BREAKPOINT_PLACEMENT) | BRK);
}

void static debuggerLoop(pid_t child_pid, FunctionData *func_data)
{
    uint64_t call_counter = 1;
    uint64_t caller_backup, callee_backup;
    struct user_regs_struct regs;
    int wait_status;

    wait(&wait_status);
    while (!WIFEXITED(wait_status))
    {
        if (func_data->undefined)
        {
            placeHookInGotOffsetPtr(child_pid, func_data->got_address, &callee_backup);
        }
        else
        {
            placeHookInFunction(child_pid, func_data->address, &callee_backup);
        }
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
        if (WIFEXITED(wait_status))
        {
            break;
        }

        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        regs.rip -= 1;
        ptrace(PTRACE_POKETEXT, child_pid, (void *)regs.rip, (void *)callee_backup);
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

        placeHookInCaller(child_pid, regs.rsp, &caller_backup);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);

        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        regs.rip -= 1;
        ptrace(PTRACE_POKETEXT, child_pid, (void *)regs.rip, (void *)caller_backup);
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

        printf("PRF:: run #%lu returned with %d\n", call_counter++, (int)regs.rax);
    }
}

void runTarget(char *argv[], FunctionData *func_data)
{
    pid_t child_pid;
    child_pid = fork();
    if (child_pid > 0)
    {
        // We are the father
        debuggerLoop(child_pid, func_data);
    }
    else if (child_pid == 0)
    {
        // We are the child
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        {
            perror("ptrace");
            exit(1);
        }
        execv(argv[0], argv);
    }
    else
    {
        // fork error
        perror("fork");
        exit(1);
    }
}
