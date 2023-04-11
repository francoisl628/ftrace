/*
** EPITECH PROJECT, 2023
** ftrace
** File description:
** ftrace
*/

#ifndef FTRACE_H_
#define FTRACE_H_

#include <stdbool.h>
#include <libelf.h>
#include <sys/user.h>

#define SYSCALL_CODE 0x050F

typedef struct data_s
{
    Elf64_Shdr *shdr;
    Elf64_Sym *symtab;
    Elf_Scn *scn;
    Elf_Data *data;
} data_t;

typedef struct func_s
{
    char *cmd;
    char **arg;
} func_t;

typedef struct symbol_s
{
    unsigned long addr;
    char *name;
    struct symbol_s *next;
    struct symbol_s *prev;
} symbol_t;

typedef struct mstack_s
{
    unsigned long addr;
    char *name;
    struct mstack_s *next;
    struct mstack_s *prev;
} mstack_t;

int start(int const ac, char const **av);
bool error_handling(int const ac);
bool init_elf(char const **av, Elf **elf);
unsigned long get_addr(symbol_t *list, char *name);
symbol_t *get_symbol(Elf **elf);
void get_arg(func_t *func, int const ac, char const **av);
int trace(symbol_t *list, func_t *func);
symbol_t *handle_list(symbol_t *list, data_t *data, Elf **elf, int i);
mstack_t *handle_list_stack(mstack_t *stack, unsigned long addr, char *name);
int find_call(pid_t pid, symbol_t *list, unsigned long rip, mstack_t **stack);
void find_ret(mstack_t *stack, unsigned long addr);
void print_syscall(struct user_regs_struct regs);
void print_enter(unsigned long rip, symbol_t *list, unsigned long srip,
mstack_t **stack);
void print_calls(symbol_t *list, mstack_t **stack, pid_t pid);
int display_help(const char *bin);
int handle_init(int const ac, char const **av);

static const int SUCCESS = 0;
static const int FAIL = 1;
static const int ERROR = 84;

static const long long unsigned int NB_SYSCALL = 328;
static const long long unsigned int EXIT = 231;

#endif /* !FTRACE_H_ */
