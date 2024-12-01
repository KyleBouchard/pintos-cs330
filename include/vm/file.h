#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

struct file_page {
	struct file_rc *file_rc;
	off_t read_bytes;
	off_t start;
	struct {
		bool is_start;
		bool is_end;
	} seq;
};

void vm_file_init (void);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
		struct file_rc *file, off_t offset);
void do_munmap (void *va);

struct mmap_arg {
	const struct cloneable_vtable *vt;
	struct file_page data;
};

extern const struct cloneable_vtable mmap_arg_vtable;

bool mmap_load_page(struct page *page, void *aux);
#endif
