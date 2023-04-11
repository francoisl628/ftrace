/*
** EPITECH PROJECT, 2023
** ftrace
** File description:
** main
*/

#include <stdio.h>
#include "ftrace.h"
#include <gelf.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include "syscall.h"
#include <stdbool.h>
#include <libelf.h>
#include <sys/user.h>

bool error_handling(int const ac)
{
    if (ac < 2) {
        fprintf(stderr, "./ftrace: must have an argument\n");
        fprintf(stderr, "Try './ftrace --help' for more information.\n");
        return true;
    }
    return false;
}

int gest_perror(const char *error)
{
    perror(error);
    return FAIL;
}

int find_call(pid_t pid, symbol_t *list, unsigned long rip, mstack_t **stack)
{
    struct user_regs_struct regs;
    int status = 0;
    unsigned ins = 0;
    unsigned char sec;

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1)
        return (gest_perror("ptrace"));
    wait(&status);
    if (WIFEXITED(status))
        return FAIL;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
        return (gest_perror("ptrace"));
    ins = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, NULL);
    sec = ((unsigned)0xFF00 & ins) >> 8;
    if (sec == 0x48)
        print_enter(regs.rip, list, rip, stack);
    return SUCCESS;
}

void find_ret(mstack_t *stack, unsigned long addr)
{
    mstack_t *tmp = stack;

    while (tmp != NULL) {
        if (tmp->addr == addr) {
            printf("Leaving function %s\n", tmp->name);
            break;
        }
        tmp = tmp->next;
    }
}

void get_arg(func_t *func, int const ac, char const **av)
{
    int i = 0;

    func->cmd = strdup(av[1]);
    if (ac > 2) {
        func->arg = malloc(sizeof(char *) * (ac));
        for (i = 1; i != ac; ++i)
            func->arg[i-1] = strdup(av[i]);
    }
    if (i == 0)
        func->arg = NULL;
    else
        func->arg[i] = NULL;
}

symbol_t *handle_symbol(Elf **elf, data_t *data)
{
    symbol_t *list = NULL;
    int size = data->shdr->sh_size / data->shdr->sh_entsize;

    data->data = elf_getdata(data->scn, NULL);
    data->symtab = (Elf64_Sym *) data->data->d_buf;
    for (int i = 0, st_type = 0; i != size; ++i) {
        st_type = ELF64_ST_TYPE(data->symtab[i].st_info);
        if (st_type == STT_FUNC || st_type == STT_NOTYPE) {
            list = handle_list(list, data, elf, i);
            if (list == NULL)
                return NULL;
        }
    }
    return list;
}

symbol_t *get_symbol(Elf **elf)
{
    data_t data;

    while ((data.scn = elf_nextscn(*elf, data.scn)) != NULL) {
        data.shdr = elf64_getshdr(data.scn);
        if (!data.shdr)
            return NULL;
        if (data.shdr->sh_type == SHT_SYMTAB)
            return handle_symbol(elf, &data);
    }
    fprintf(stderr, "Error: no symbol found.\n");
    return NULL;
}

mstack_t *create_node(unsigned long addr, char *name)
{
    mstack_t *new = malloc(sizeof(mstack_t));

    if (new == NULL)
        return NULL;
    new->addr = addr;
    new->name = name;
    new->next = NULL;
    new->prev = NULL;
    return new;
}

mstack_t *handle_list_stack(mstack_t *stack, unsigned long addr, char *name)
{
    mstack_t *new = create_node(addr, name);
    mstack_t *tmp = stack;

    if (stack == NULL)
        return new;
    while (tmp->next != NULL)
        tmp = tmp->next;
    tmp->next = new;
    new->prev = tmp;
    return stack;
}

unsigned long get_addr(symbol_t *list, char *name)
{
    symbol_t *tmp = list;

    while (tmp != NULL)
    {
        if (!strcmp(tmp->name, name))
            return tmp->addr;
        tmp = tmp->next;
    }
    return 0;
}

bool gest_error(const char *error, const char *perror_err)
{
    if (perror_err != NULL)
        perror(perror_err);
    fprintf(stderr, error);
    return true;
}

bool read_elf(char const **av, Elf **elf, int fd)
{
    if (elf_version(EV_CURRENT) == EV_NONE)
        return (gest_error("Error: elf\n", NULL));
    *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (*elf == NULL)
        return (gest_error("Error: elf\n", "elf_begin"));
    if (elf_kind(*elf) != ELF_K_ELF) {
        fprintf(stderr, "Error: %s isn't an elf file\n", av[1]);
        return true;
    }
    return false;
}

bool init_elf(char const **av, Elf **elf)
{
    int fd = open(av[1], O_RDONLY, NULL);

    if (fd < 0)
        return (gest_error("Error: open failed\n", "open"));
    if (read_elf(av, elf, fd) || gelf_getclass(*elf) != ELFCLASS64)
        return true;
    return false;
}

int main(int const ac, char const **av)
{
    return start(ac, av);
}

void display_args(struct user_regs_struct reg)
{
    size_t regs[6] = {reg.rdi, reg.rsi, reg.rdx,
                        reg.rcx, reg.r8, reg.r9};
    size_t orig = reg.orig_rax;

    printf("Syscall %s(", entries[orig].name);
    for (int i = 0; i != entries[orig].nb_args; ++i) {
        printf("0x%lx", regs[i]);
        if (i != entries[orig].nb_args - 1)
            printf(", ");
    }
    printf(") = ");
    if (orig == EXIT || orig == 162) {
        printf("?\n");
        return;
    }
    printf("0x%llx\n", reg.rax);
}

void print_syscall(struct user_regs_struct regs)
{
    size_t orig = regs.orig_rax;

    if ((int)orig == -1)
        return;
    if (orig > NB_SYSCALL) {
        printf("Unknown\n");
        return;
    }
    display_args(regs);
    if (orig == EXIT) {
        printf("Leaving function main\n");
        printf("+++ exited with %lld +++\n", regs.rdi);
    }
}

void print_enter(unsigned long rip, symbol_t *list, unsigned long srip,
mstack_t **stack)
{
    symbol_t *tmp = list;

    while (tmp != NULL) {
        if (rip == tmp->addr && tmp->name[0] != '_') {
            printf("Entering function %s at %#lx\n", tmp->name, tmp->addr);
            *stack = handle_list_stack(*stack, srip, tmp->name);
            break;
        }
        tmp = tmp->next;
    }
}

int display_help(const char *bin)
{
    printf("USAGE: %s <command>\n", bin);
    return SUCCESS;
}

void print_calls(symbol_t *list, mstack_t **stack, pid_t pid)
{
    unsigned ins = 0;
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    ins = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, NULL);
    if (((unsigned) 0xFF & ins) == 0xE8)
        find_call(pid, list, regs.rip, stack);
    else if (((unsigned) 0xFF & ins) == 0xC3)
        find_ret(*stack, ptrace(PTRACE_PEEKTEXT, pid, regs.rsp, 0) - 5);
    else
        print_syscall(regs);
}
