/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "bitmap.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/string.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static struct bitmap *swap_map;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* Set up the swap_disk. */
	swap_disk = disk_get(1, 1);

	lock_acquire(&io_lock);
	swap_map = bitmap_create((disk_size(swap_disk) * DISK_SECTOR_SIZE) / PGSIZE);
	lock_release(&io_lock);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;

	anon_page->type = type;
	anon_page->swapped_out = false;

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	uint8_t buffer[DISK_SECTOR_SIZE];

	if (!anon_page->swapped_out)
		return true;

	for (size_t i = 0; i < PGSIZE / DISK_SECTOR_SIZE; i++)
	{
		lock_acquire (&io_lock);
		disk_read (swap_disk, anon_page->id * (PGSIZE / DISK_SECTOR_SIZE) + i, buffer);
		lock_release (&io_lock);
		memcpy (kva, buffer, sizeof(buffer));
		*(uintptr_t *)&kva += DISK_SECTOR_SIZE;
	}

	anon_page->swapped_out = false;

	bitmap_reset(swap_map, anon_page->id);

	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	if (anon_page->swapped_out)
		return true;

	size_t id = bitmap_scan_and_flip (swap_map, 0, 1, false);
	if (id == BITMAP_ERROR)
		return false;
	
	anon_page->id = id;

	for (size_t i = 0; i < PGSIZE / DISK_SECTOR_SIZE; i++)
	{
		void *addr = (void *)((uintptr_t)page->va + DISK_SECTOR_SIZE * i);
		lock_acquire (&io_lock);
		disk_write (swap_disk, anon_page->id * (PGSIZE / DISK_SECTOR_SIZE) + i, addr);
		lock_release (&io_lock);
	}

	anon_page->swapped_out = true;

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	if (anon_page->swapped_out)
		bitmap_reset(swap_map, anon_page->id);
}
