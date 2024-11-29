/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/string.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, struct cloneable *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = NULL;

	// We must have a way to clone the aux
	if (aux && !aux->clone)
		goto err;

	/* Check whether the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		page = malloc(sizeof(struct page));
		if (!page)
			goto err;
		
		bool (*initializer)(struct page *, enum vm_type, void *);
		switch (VM_TYPE(type)) {
			case VM_ANON:
				initializer = anon_initializer;
				break;
			case VM_FILE:
				initializer = file_backed_initializer;
				break;
			default:
				goto err;
		}

		uninit_new(page, upage, init, type, aux, initializer);
		/* TODO: Insert the page into the spt. */
		spt_insert_page(spt, page);

		return true;
	}
err:
	if (page)
		free(page);
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct list_elem *p;
	struct page *page;

	void *page_va = (uintptr_t)va - ((uintptr_t)va % PGSIZE);

	for (p = list_begin (&spt->pages); p != list_end (&spt->pages); p = list_next (p)) {
		page = list_entry (p, struct page, elem);

		if (page->va == page_va) {
			return page;
		}	
	}

	return NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
	/* TODO: Fill this function. */
	if (spt_find_page (spt, page->va))
		return false;

	list_push_back(spt, &page->elem);
	return true;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	list_remove(&page->elem);
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
	/* TODO: Fill this function. */
	
	if (!frame)
		return NULL;
	
	frame->kva = palloc_get_page(PAL_USER);
	if (!frame->kva) {
		free(frame);
		PANIC ("todo");
	}

	frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
	void *base = pg_round_down(addr);

	if (
		(uintptr_t)base > USER_STACK ||
		(uintptr_t)base < USER_STACK - (1 << 20) // 1MB
	)
		return;
		
	while (!spt_find_page(&thread_current ()->spt, base)) {
		if (
			!vm_alloc_page(VM_ANON | VM_MARKER_0, base, true) ||
			!vm_claim_page(base)
		)
			return;
	
		base = base + PGSIZE;
	}
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write, bool not_present) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = spt_find_page(spt, addr);
	
	// check stack expansion
	do {
		bool is_stack_expansion = false;

		// must be user and page must not exist yet
		if (!user || page)
			break;
		
		uintptr_t candidate = (uintptr_t)addr;

		// we accept anything 8 bytes before rsp
		if (
			candidate < f->rsp - 8 ||
			candidate > USER_STACK ||
			candidate < USER_STACK - (1 << 20) // 1MB
		)
			break;
		
		uintptr_t page_base = pg_round_down(candidate);
		while (page_base < USER_STACK) {
			page_base += PGSIZE; // skip first page as we already know it isn't present

			page = spt_find_page(spt, (void *)page_base);
			if (!page)
				continue;
			
			is_stack_expansion = VM_TYPE(page->operations->type) == VM_ANON && (page->anon.type & VM_MARKER_0) != 0;
			break;
		}

		if (is_stack_expansion) {
			vm_stack_growth(addr);
			return true;
		}
	} while (false);

	/* TODO: Validate the fault */
	if (!page || VM_TYPE(page->operations->type) != VM_UNINIT || !vm_do_claim_page (page)) {
		return false;
	}

	/* TODO: Your code goes here */

	return true;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
	struct page *page = spt_find_page(&thread_current ()->spt, va);
	if (!page)
		return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* Insert page table entry to map page's VA to frame's PA. */
	if (
		!pml4_set_page(thread_current ()->pml4, page->va, frame->kva, true) || // TODO? RW
		!swap_in (page, frame->kva)
	) {
		pml4_clear_page(thread_current ()->pml4, page->va);
		free(frame); // TODO wtf is this? garbage
		return false;
	}

	return true;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	list_init(&spt->pages);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	struct list_elem *p;
	struct page *page, *copy;
	bool success = false;

	for (p = list_begin (&src->pages); p != list_end (&src->pages); p = list_next (p)) {
		page = list_entry (p, struct page, elem);

		copy = malloc(sizeof(*copy));
		if (!copy)
			goto out;

		bool (*initializer)(struct page *, enum vm_type, void *);
		vm_initializer *init = NULL;
		struct cloneable *aux_cloneable = NULL;
		enum vm_type type = page->operations->type;
		bool was_claimed = false;
		switch (VM_TYPE(type)) {
			case VM_UNINIT: {
				if (page->uninit.aux) {
					aux_cloneable = (struct cloneable *)malloc(sizeof(*aux_cloneable));
					if (!aux_cloneable)
						goto loop_err;
					
					struct cloneable *orig_aux_cloneable = (struct cloneable *)page->uninit.aux;
					aux_cloneable->aux = orig_aux_cloneable->clone(orig_aux_cloneable->aux);
					if (!aux_cloneable->aux)
						goto loop_err;
					
					aux_cloneable->clone = orig_aux_cloneable->clone;
					aux_cloneable->free = orig_aux_cloneable->free;
				}

				was_claimed = true;
				initializer = page->uninit.page_initializer;
				init = page->uninit.init;
				type = page->uninit.type;
				break;
			}
			case VM_ANON: {
				initializer = anon_initializer;
				break;
			}
			case VM_FILE: {
				initializer = file_backed_initializer;
				break;
			}
			default: {
				goto loop_err;
			}
		}

		uninit_new(copy, page->va, init, type, aux_cloneable, initializer);
		spt_insert_page(dst, copy);

		if (!was_claimed) {
			if (!vm_do_claim_page(copy))
				goto out;

			memcpy(copy->frame->kva, page->frame->kva, PGSIZE);
		}

		continue;
loop_err:
		if (copy)
			free(copy);
		if (aux_cloneable)
			free(aux_cloneable);
		goto out;
	}

	success = true;

out:
	return success;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	struct page* page, *copy;
    struct list_elem* e;
	while (!list_empty(&spt->pages)) {
		e = list_begin(&spt->pages);
		page = list_entry (e, struct page, elem);
		spt_remove_page(spt, page);
	}
}
