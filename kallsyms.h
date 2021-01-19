#ifndef TCPSECRETS_KALLSYMS_H
#define TCPSECRETS_KALLSYMS_H

#ifdef __KERNEL__

#include <linux/kernel.h>
#include <linux/string.h>

#else /* user mode test */

#include <stdio.h>
#include <string.h>

static char* strnchr(char *s, size_t n, int ch)
{
    return memchr(s, ch, n);
}

#endif /* kernel mode */

#define PARSE_OK 0
#define PARSE_ERR_NOTFOUND 1
#define PARSE_ERR_LINETOOLONG 2
#define PARSE_ERR_READ 3

typedef void *file_type;

typedef ssize_t (*read_type)(file_type file, void *buffer, size_t count);

static unsigned long parse_kallsyms_line(const char *begin, const char *end)
{
	static const int NAME_OFFSET = 16 + 1 + 1 + 1;

	const char *name;
	unsigned long addr;

	if ((end - begin) <= NAME_OFFSET)
		return 0;

	name = begin + NAME_OFFSET;
	if (strncmp(name, "kallsyms_on_each_symbol", end - name))
		return 0;

	sscanf(begin, "%016lx", &addr);
	return addr;
}

static int parse_kallsyms_file(file_type f, read_type read, unsigned long *addr)
{
	char buffer[1024] = {0};       /* current input chunk */
	char leftover[128] = {0};      /* unterminated line from previous chunk */
	char *leftover_end = leftover; /* place to put line continuation */
	ssize_t ret;

	while ((ret = read(f, buffer, sizeof(buffer))) > 0) {
		char *begin = buffer;
		char *end = strnchr(buffer, ret, '\n');
		if (!end) {
			return PARSE_ERR_LINETOOLONG;
		}

		if (leftover != leftover_end) {
			/* check if second piece of line fits in leftover */
			size_t size = end - buffer;
			if ((leftover_end + size) >= (leftover + sizeof(leftover))) {
				return PARSE_ERR_LINETOOLONG;
			}

			strncpy(leftover_end, buffer, size);
			leftover_end += end - buffer;
			if ((*addr = parse_kallsyms_line(leftover, leftover_end)))
				return PARSE_OK;

			/* clear leftover and move to next line */
			leftover_end = leftover;
			begin = end + 1;
		}

		while ((end = strnchr(begin, buffer + ret - begin, '\n'))) {
			if ((*addr = parse_kallsyms_line(begin, end)))
				return PARSE_OK;
			begin = end + 1;
		}

		/* stash last line if it's not terminated */
		if (begin < (buffer + ret)) {
			size_t size = buffer + ret - begin;
			strncpy(leftover, begin, size);
			leftover_end = leftover + size;
		}
	}

	if (ret < 0)
		return PARSE_ERR_READ;
	return PARSE_ERR_NOTFOUND;
}

#endif
