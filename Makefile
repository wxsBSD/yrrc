CC = gcc

all:
	$(CC) -o yrrc -I./yara_build/libyara/include -L./yara_build/libyara/.libs -lyara yrrc.c cJSON.c collect.c utils.c scan.c
