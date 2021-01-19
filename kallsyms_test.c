#include "kallsyms.h"

#define TEST(x) do { \
	if (!(x)) { \
		printf("Test FAILED: %s, line %d\n", __func__, __LINE__); \
		return; \
	} \
} while (0)

struct file {
	const char* source;
	size_t size;
	size_t offset;
	size_t chunk_size;
	size_t fail_after;
};

void new_file(struct file *file, const char *source)
{
	file->source = source;
	file->size = strlen(source);
	file->offset = 0;
	file->chunk_size = 64;
	file->fail_after = file->size + 1;
}

ssize_t read_file(file_type f, void *buffer, size_t size)
{
	struct file *file = (struct file *)f;
	size_t available;

	if (file->offset >= file->fail_after)
		return -1;

	available = file->size - file->offset;
	if (available > size)
		available = size;
	if (available > file->chunk_size)
		available = file->chunk_size;

	memcpy(buffer, file->source + file->offset, available);
	file->offset += available;
	return available;
}

void test_presence(void)
{
	struct file file;
	int ret;
	unsigned long addr;

	new_file(&file,
		"ffffffffa531e950 t s_show\n"
		"ffffffffa531e9e0 t kallsyms_expand_symbol.constprop.0\n"
		"ffffffffa531ea70 T kallsyms_on_each_symbol\n"
		"ffffffffa531eb30 T kallsyms_lookup_name\n"
		"ffffffffa531f0c0 W arch_get_kallsym\n");

	ret = parse_kallsyms_file(&file, read_file, &addr);
	TEST(ret == PARSE_OK);
	TEST(addr == 0xffffffffa531ea70);
}

void test_absence(void)
{
	struct file file;
	int ret;
	unsigned long addr;

	new_file(&file,
		"ffffffffa5200000 T startup_64\n"
		"ffffffffa5200000 T _stext\n"
		"ffffffffa52000e0 T verify_cpu\n"
		"ffffffffa52001e0 T start_cpu0\n"
		"ffffffffa52001f0 T __startup_64\n"
		"ffffffffa5201000 t xen_hypercall_set_trap_table\n"
		"ffffffffa5201020 t xen_hypercall_mmu_update\n");
	ret = parse_kallsyms_file(&file, read_file, &addr);
	TEST(ret == PARSE_ERR_NOTFOUND);
	TEST(addr == 0);
}

void test_similar_prefix(void)
{
	struct file file;
	int ret;
	unsigned long addr;

	new_file(&file,
		"ffffffffa531dfa0 T module_get_kallsym\n"
		"ffffffffa531e0f0 T module_kallsyms_lookup_name\n"
		"ffffffffa531ea70 T kallsyms_on_each_symbol.cold.0\n"
		"ffffffffa531ea70 T kallsyms_on_each_symbol\n"
		"ffffffffa531eb30 T kallsyms_lookup_name\n"
		"ffffffffa531ebe0 T kallsyms_lookup_size_offset\n");
	ret = parse_kallsyms_file(&file, read_file, &addr);
	TEST(ret == PARSE_OK);
	TEST(addr == 0xffffffffa531ea70);
}

void test_similar_suffix(void)
{
	struct file file;
	int ret;
	unsigned long addr;

	new_file(&file,
		"ffffffffa531dfa0 T module_get_kallsym\n"
		"ffffffffa531e0f0 T module_kallsyms_lookup_name\n"
		"ffffffffa531e180 T module_kallsyms_on_each_symbol\n"
		"ffffffffa531e210 T search_module_extables\n"
		"ffffffffa531e250 T is_module_address\n"
		"ffffffffa531e950 t s_show\n"
		"ffffffffa531e9e0 t kallsyms_expand_symbol.constprop.0\n"
		"ffffffffa531ea70 T kallsyms_on_each_symbol\n"
		"ffffffffa531eb30 T kallsyms_lookup_name\n"
		"ffffffffa531ebe0 T kallsyms_lookup_size_offset\n");
	ret = parse_kallsyms_file(&file, read_file, &addr);
	TEST(ret == PARSE_OK);
	TEST(addr == 0xffffffffa531ea70);
}

void test_addr_split(void)
{
	struct file file;
	int ret;
	unsigned long addr;

	new_file(&file,
		"ffffffffa531e950 t s_show\n"
		"ffffffffa531e9e0 t kallsyms_expand_symbol\n"
		"ffffffffa531ea70 T kallsyms_on_each_symbol\n"
		"ffffffffa531eb30 T kallsyms_lookup_name\n"
		"ffffffffa531f0c0 W arch_get_kallsym\n");
	file.chunk_size = 72;

	ret = parse_kallsyms_file(&file, read_file, &addr);
	TEST(ret == PARSE_OK);
	TEST(addr == 0xffffffffa531ea70);
}

void test_name_split(void)
{
	struct file file;
	int ret;
	unsigned long addr;

	new_file(&file,
		"ffffffffa531e950 t s_show\n"
		"ffffffffa531e9e0 t kallsyms_expand_symbol\n"
		"ffffffffa531ea70 T kallsyms_on_each_symbol\n"
		"ffffffffa531eb30 T kallsyms_lookup_name\n"
		"ffffffffa531f0c0 W arch_get_kallsym\n");
	file.chunk_size = 100;

	ret = parse_kallsyms_file(&file, read_file, &addr);
	TEST(ret == PARSE_OK);
	TEST(addr == 0xffffffffa531ea70);
}

void test_line_overflow(void)
{
	struct file file;
	int ret;
	unsigned long addr;

	new_file(&file,
		"ffffffffa531e950 t s_show\n"
		"ffffffffa531e9e0 t whatever_long_name_i_can_try_to_creatively_invent\n"
		"ffffffffa531ea70 T kallsyms_on_each_symbol\n"
		"ffffffffa531eb30 T kallsyms_lookup_name\n"
		"ffffffffa531f0c0 W arch_get_kallsym\n");
	file.chunk_size = 32;

	ret = parse_kallsyms_file(&file, read_file, &addr);
	TEST(ret == PARSE_ERR_LINETOOLONG);
	TEST(addr == 0);
}

void test_read_error(void)
{
	struct file file;
	int ret;
	unsigned long addr;

	new_file(&file,
		"ffffffffa531e950 t s_show\n"
		"ffffffffa531e9e0 t kallsyms_expand_symbol.constprop.0\n"
		"ffffffffa531ea70 T kallsyms_on_each_symbol\n"
		"ffffffffa531eb30 T kallsyms_lookup_name\n"
		"ffffffffa531f0c0 W arch_get_kallsym\n");
	file.chunk_size = 32;
	file.fail_after = 20;

	ret = parse_kallsyms_file(&file, read_file, &addr);
	TEST(ret == PARSE_ERR_READ);
	TEST(addr == 0);
}

int main(void)
{
	test_presence();
	test_absence();
	test_similar_prefix();
	test_similar_suffix();
	test_addr_split();
	test_name_split();
	test_line_overflow();
	test_read_error();
}
