#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif
#include "fixed-point.h"
#include "synch.h"
#ifdef USERPROG
#include "filesys/file.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_NULL -1						/* Null priority. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

struct file_rc {
	struct file *file;
	size_t reference_count;
	struct lock reference_count_lock;
};

struct file_rc *file_rc_open(const char *);
struct file_rc *file_rc_clone(struct file_rc *);
void file_rc_own(struct file_rc *);
void file_rc_disown(struct file_rc *);

#ifdef USERPROG
struct thread_exit_status {
	tid_t pid;							/* Child process stored. */
	int exit_status;					/* Child process exit status. */
	struct semaphore event;             /* Update when died. */
	size_t reference_count;				/* Reference count to the number of thread that have a pointer on it. */
	struct lock reference_count_lock;	/* Lock for reference count int. */
	struct list_elem elem;				/* List elem. */
};

bool thread_exit_status_new(struct thread *thread);
int thread_exit_status_wait(struct thread_exit_status *exit_status);
void thread_exit_status_own(struct thread_exit_status *exit_status);
void thread_exit_status_disown(struct thread_exit_status *exit_status);

enum file_descriptor_kind {
	FD_KIND_FILE,
	FD_KIND_STDIN,
	FD_KIND_STDOUT,
};

struct file_descriptor {
	struct file_rc *file;                  /* Underlying file pointer */
	struct list_elem elem;              /* Next file */
	int fd;                             /* File descriptor number */
	enum file_descriptor_kind kind;
};

struct file_descriptor* thread_find_file_descriptor(int fd);
struct file_descriptor* file_descriptor_open(const char *);
struct file_descriptor* file_descriptor_reopen(struct file_descriptor*);
struct file_descriptor* file_descriptor_duplicate(struct file_descriptor* file_descriptor, int fd);
void file_descriptor_close(struct file_descriptor*);
#endif

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Base priority. */
	union {
		struct {
			int donation;               /* Priority donation received. */
			struct list locks;          /* Locks currently owned. */
			struct lock *blocked_on;    /* Lock currently blocked on. */
		} donation;
		struct {
			int nice;                   /* Nice value. */
			floater recent_cpu;
			struct list_elem elem;      
		} mlfqs;
	};

	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */

#ifdef USERPROG
	bool user_mode;
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
	struct list children; 				/* Children of the process. */
	struct thread_exit_status* exit_status;		/* Status referenced by parent. */
	struct {
		struct list list;
		int next_fd;
		struct lock next_fd_lock;
	} file_descriptors;
	struct file *executable_file;
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);
bool thread_compare(const struct list_elem *a,
				 	const struct list_elem *b,
                 	void *aux);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
int thread_get_effective_priority (struct thread *thread);
void thread_set_priority (int);
bool
thread_less_priority (const struct list_elem *a,
		const struct list_elem *b, void *aux UNUSED);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);

#endif /* threads/thread.h */
