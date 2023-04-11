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

//isok
symbol_t *handle_list(symbol_t *list, data_t *data, Elf **elf, int i)
{
    char *name = elf_strptr(*elf, data->shdr->sh_link, data->symtab[i].st_name);
    symbol_t *node = malloc(sizeof(symbol_t));
    if (node == NULL) {
        return NULL;
    }
    node->addr = data->symtab[i].st_value;
    node->name = strdup(name);
    node->prev = NULL;
    node->next = NULL;

    if (list == NULL) {
        return node;
    } else {
        symbol_t *tail = list;
        while (tail->next != NULL) {
            tail = tail->next;
        }
        tail->next = node;
        node->prev = tail;
        return list;
    }
}
 
//done
bool start_trace(func_t *func)
{
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        perror("ptrace");
        return true;
    }
    if (execvp(func->cmd, &func->arg[0]) == -1) {
        perror("execvp");
        return true;
    }
    return false;
}

//done
int handle_init(int const argc, char const **argv) {
    Elf *elf;
    if (init_elf(argv, &elf)) {
        return 1;
    }
    symbol_t *calc = get_symbol(&elf);
    if (calc == NULL) {
        elf_end(elf);
        return 1;
    }
    func_t function;
    get_arg(&function, argc, argv);
    trace(calc, &function);
    elf_end(elf);
    return 0;
}

//done
int init_and_trace(int const argc, char const **argv) {
    if (handle_init(argc, argv) != SUCCESS) {
        return FAIL;
    }
    return SUCCESS;
}


bool trace_and_print(pid_t pid, symbol_t *list)
{
    int wait_status;
    mstack_t *value;

    wait(&wait_status);
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEEXIT) == -1) {
        perror("ptrace");
        return true;
    }
    while (!WIFEXITED(wait_status)) {
        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        wait(&wait_status);
        if (WIFEXITED(wait_status)) {
			break;
        }
        print_calls(list, &value, pid);
    }
    return false;
}

//done
bool tracerBool(pid_t pid, symbol_t *list)
{
    return trace_and_print(pid, list);
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
