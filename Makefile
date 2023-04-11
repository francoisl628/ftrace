##
## EPITECH PROJECT, 2023
## strace2
## File description:
## Makefile
##


CC	= gcc

RM	= rm -f


NAME	= mymy

SRCS	= ./main.c	\
		  ./main2.c

OBJS	= $(SRCS:.c=.o)

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(OBJS) -l elf -o $(NAME)

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAME)

re: fclean all

.PHONY:	all clean fclean re
