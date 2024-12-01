/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "threads/malloc.h"
#include "threads/mmu.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;

	file_page->file_rc = NULL;
	file_page->read_bytes = 0;
	file_page->start = 0;
	file_page->seq.is_start = true;
	file_page->seq.is_end = true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page = &page->file;
	lock_acquire (&io_lock);
	off_t actual_read_bytes = file_read_at (
		file_page->file_rc->file,
		page->frame->kva,
		file_page->read_bytes,
		file_page->start
	);
	lock_release (&io_lock);

	if (actual_read_bytes < 0)
		return false;

	memset((uint8_t *)page->frame->kva + actual_read_bytes, 0, PGSIZE - actual_read_bytes);

	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page = &page->file;
	if (!pml4_is_dirty(thread_current()->pml4, page->va))
		return true;

	lock_acquire (&io_lock);
	off_t actual_written_bytes = file_write_at (
		file_page->file_rc->file,
		page->va,
		file_page->read_bytes,
		file_page->start
	);
	lock_release (&io_lock);

	pml4_set_dirty(thread_current()->pml4, page->va, false);

	if (actual_written_bytes != file_page->read_bytes)
		return false;

	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page = &page->file;

	if (page->frame)
		swap_out(page);

	file_rc_disown(file_page->file_rc);
}

static void *
mmap_arg_clone(void *aux) {
	struct mmap_arg *arg = (struct mmap_arg *)aux,
					*new = (struct mmap_arg *)malloc(sizeof(struct mmap_arg));
	
	if (!new)
		return NULL;

	memcpy(new, arg, sizeof(struct mmap_arg));

	if (!(new->data.file_rc = file_rc_clone(arg->data.file_rc))) {
		free(new);
		return NULL;
	}

	return new;
}

static void
mmap_arg_free(void *aux) {
	struct mmap_arg *arg = (struct mmap_arg *)aux;
	
	file_rc_disown(arg->data.file_rc);

	free(arg);
}

const struct cloneable_vtable mmap_arg_vtable = {
	.clone = mmap_arg_clone,
	.free = mmap_arg_free
};

bool
mmap_load_page(struct page *page, void *aux) {
	struct file_page *file_page = &page->file;
	struct mmap_arg *arg = (struct mmap_arg *)aux;

	// increment since freeing the arg will decrement
	file_rc_own(arg->data.file_rc);
	memcpy(file_page, &arg->data, sizeof(*file_page));

	bool success = swap_in(page, page->frame->kva);

	arg->vt->free(arg);

	return success;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file_rc *file_rc, off_t offset) {
	if (pg_ofs(addr) != 0 || addr == NULL || length == 0 || offset < 0 || offset % PGSIZE != 0)
		return NULL;

	for (uintptr_t i = (uintptr_t) addr; i < (uintptr_t) addr + length; i+=PGSIZE)
	{
		if (spt_find_page(&thread_current()->spt, (void *)i)) {
			return NULL;
		}
	}

	off_t filesize = file_length(file_rc->file);
	if (filesize < offset)
		return NULL;

	if (filesize < length)
		length = filesize;

	struct mmap_arg *arg;

	for (uintptr_t i = (uintptr_t) addr; i < (uintptr_t) addr + length; i+=PGSIZE) {
		arg = malloc(sizeof(struct mmap_arg));
		if (!arg)
			return NULL;
		
		arg->vt = &mmap_arg_vtable;
		arg->data.file_rc = file_rc;
		arg->data.read_bytes = length + (uintptr_t)addr - i;
		if (arg->data.read_bytes > PGSIZE)
			arg->data.read_bytes = PGSIZE;

		arg->data.start = offset + i - (uintptr_t)addr;

		arg->data.seq.is_start = i == (uintptr_t)addr;
		arg->data.seq.is_end = i + PGSIZE >= (uintptr_t)addr + length;

		// Increment refcnt to be decremented lazily.
		file_rc_own(file_rc);
		if (!vm_alloc_page_with_initializer (VM_FILE, i,
					writable, mmap_load_page, &(arg->vt))) {
			arg->vt->free(arg);
			return NULL;
		}
	}

	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	// Know what are all the maps at this address
	if (pg_ofs(addr) != 0)
		return;

	bool is_first = true;
	bool is_last = false;

	do {
		struct page *page = spt_find_page(&thread_current()->spt, addr);
		if (!page || page_get_type(page) != VM_FILE)
			return;

		bool uninit = VM_TYPE(page->operations->type) == VM_UNINIT;
		struct file_page *file_page = uninit
			? &((struct mmap_arg *)page->uninit.aux)->data
			: &page->file;
		
		if (
			(file_page->seq.is_start && !is_first) ||
			(!file_page->seq.is_start && is_first)
		)
			return;

		is_first = false;
		is_last = file_page->seq.is_end;

		spt_remove_page(&thread_current()->spt, page);

		*(uintptr_t *)&addr += PGSIZE; 
	} while (!is_last);	
}
