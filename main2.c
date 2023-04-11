/*
** EPITECH PROJECT, 2023
** ftrace
** File description:
** main2
*/

#include "ftrace.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <sys/wait.h>
#include <string.h>
#include <pthread.h>

int start(int const ac, char const **av)
{
    if (ac == 2 && !strcmp(av[1], "--help"))
        return display_help(av[0]);
    if (error_handling(ac))
        return ERROR;
    if (handle_init(ac, av))
        return ERROR;
    return SUCCESS;
}

static symbol_t *create_node(unsigned long addr, char *name)
{
    symbol_t *new = malloc(sizeof(symbol_t));
    
    if (new == NULL) {
        perror("malloc");
        return NULL;
    }
    new->addr = addr;
    new->name = name;
    new->next = NULL;
    new->prev = NULL;
    return new;
}

symbol_t *handle_list(symbol_t *list, data_t *data, Elf **elf, int i)
{
    symbol_t *new = create_node(data->symtab[i].st_value,
    elf_strptr(*elf, data->shdr->sh_link, data->symtab[i].st_name));
    symbol_t *tmp = list;

    if (list == NULL)
        return new;
    while (tmp->next != NULL)
        tmp = tmp->next;
    tmp->next = new;
    new->prev = tmp;
    return list;
}

static bool gest_perror(const char *error)
{
    perror(error);
    return true;
}

static bool start_trace(func_t *func)
{
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
        return (gest_perror("ptrace"));
    if (execvp(func->cmd, &func->arg[0]) == -1)
        return (gest_perror("execvp"));
    return false;
}

int handle_init(int const ac, char const **av)
{
    Elf *elf;
    symbol_t *sym = NULL;
    func_t func;

    if (init_elf(av, &elf))
        return FAIL;
    sym = get_symbol(&elf);
    if (sym == NULL)
        return FAIL;
    get_arg(&func, ac, av);
    trace(sym, &func);
    elf_end(elf);
    return SUCCESS;
}

static bool tracerBool(pid_t pid, symbol_t *list)
{
    int status = 0;
    mstack_t *stack;

    wait(&status);
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEEXIT) == -1)
        return (gest_perror("ptrace"));
    while (!WIFEXITED(status)) {
        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        wait(&status);
        if (WIFEXITED(status))
			break;
        print_calls(list, &stack, pid);
    }
    return false;
}


//done
int trace(symbol_t *list, func_t *func) {
    pid_t pid = fork();

    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    else if (pid == 0) {
        if (start_trace(func)) {
            exit(EXIT_FAILURE);
        }
        else {
            exit(EXIT_SUCCESS);
        }
    }
    else {
        printf("Entering function main at %#lx\n", get_addr(list, "main"));
        tracerBool(pid, list);
        return FAIL;
    }
    return SUCCESS;
}
