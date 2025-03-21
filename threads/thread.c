#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all threads. Only used with mlfqs. */
static struct list thread_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */
static floater load_avg;        /* Average # of threads ready to run. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

struct lock io_lock;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Calculates next value for load_avg and returns it. */
static floater
thread_calc_load_avg(void) {
	ASSERT(thread_mlfqs);

	int ready_threads = list_size(&ready_list);

	if (thread_current () != idle_thread)
		++ready_threads;

	return floater_add_floater(
		floater_mul_floater(
			load_avg, 
			floater_div_floater(
				floater_from_int(59), floater_from_int(60)
			)
		),
		floater_mul_int(
			floater_div_floater(
				floater_from_int(1), floater_from_int(60)
			),
			ready_threads
		)
	);
}

/* Calculates next value for a thread's recent_cpu and returns it. */
static floater
thread_calc_recent_cpu (struct thread* t) {
	ASSERT(thread_mlfqs);
	
	return floater_add_int(
		floater_mul_floater(
			floater_div_floater(
				floater_mul_int(load_avg, 2),
				floater_add_int(floater_mul_int(load_avg, 2), 1)
			),
			t->mlfqs.recent_cpu
		),
		t->mlfqs.nice
	);
}

static int
thread_calc_priority (struct thread* t) {
	ASSERT(thread_mlfqs);
	
	int priority = floater_to_int_trunc(
		floater_sub_floater(
			floater_from_int(PRI_MAX),
			floater_add_int(
				floater_div_int(t->mlfqs.recent_cpu, 4),
				t->mlfqs.nice * 2
			)
		)
	);

	if (priority < PRI_MIN) return PRI_MIN;
	if (priority > PRI_MAX) return PRI_MAX;
	return priority;
}

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&destruction_req);

	lock_init (&io_lock);

	/* Initialize statistics. */
	if (thread_mlfqs) {
		list_init (&thread_list);
		load_avg = floater_from_int(0);
	}

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();

	init_thread (initial_thread, "main", PRI_DEFAULT);
	if (thread_mlfqs) {
		initial_thread->mlfqs.nice = 0;
		initial_thread->mlfqs.recent_cpu = 0;
		initial_thread->priority = thread_calc_priority(initial_thread);
		list_push_back (&thread_list, &initial_thread->mlfqs.elem);
	}

	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	if (thread_mlfqs) {
		int64_t ticks = timer_ticks ();
		if (ticks % TIMER_FREQ == 0) {
			load_avg = thread_calc_load_avg();

			for (
				struct list_elem *it = list_begin(&thread_list);
				it != list_end(&thread_list);
				it = list_next(it)
			) {
				struct thread *ithread = list_entry (it, struct thread, mlfqs.elem);
				ithread->mlfqs.recent_cpu = thread_calc_recent_cpu (ithread);
			}
		}

		if (ticks % 4 == 0) {
			for (
				struct list_elem *it = list_begin(&thread_list);
				it != list_end(&thread_list);
				it = list_next(it)
			) {
				struct thread *ithread = list_entry (it, struct thread, mlfqs.elem);
				ithread->priority = thread_calc_priority (ithread);
			}
		}

		if (t != idle_thread)
			t->mlfqs.recent_cpu = floater_add_int(t->mlfqs.recent_cpu, 1);
	}


	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

bool
thread_less_priority (const struct list_elem *a,
		const struct list_elem *b, void *aux UNUSED) {
	return thread_get_effective_priority (list_entry (a, struct thread, elem))
		< thread_get_effective_priority (list_entry (b, struct thread, elem));
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);
	if (thread_mlfqs) {
		t->mlfqs.nice = thread_get_nice ();
		t->mlfqs.recent_cpu = thread_get_recent_cpu ();
		t->priority = thread_calc_priority(t);
		list_push_back (&thread_list, &t->mlfqs.elem);
	}

	tid = t->tid = allocate_tid ();

#ifdef USERPROG
	struct file_descriptor *fd_stdin = NULL, *fd_stdout = NULL;

    if (!thread_exit_status_new(t)) {
		goto err;
	}

	fd_stdin = (struct file_descriptor *)malloc(sizeof(*fd_stdin));
	fd_stdout = (struct file_descriptor *)malloc(sizeof(*fd_stdin));
	if (!fd_stdin || !fd_stdout)
		goto err;
	
	fd_stdin->kind = FD_KIND_STDIN;
	fd_stdin->file = NULL;
	fd_stdin->fd = 0;
    list_push_back (&t->file_descriptors.list, &fd_stdin->elem);

	fd_stdout->kind = FD_KIND_STDOUT;
	fd_stdout->file = NULL;
	fd_stdout->fd = 1;
    list_push_back (&t->file_descriptors.list, &fd_stdout->elem);

    thread_exit_status_own (t->exit_status);
    list_push_back (&thread_current ()->children, &t->exit_status->elem);

	t->user_mode = false;
#endif

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock (t);

	if (thread_get_priority() < thread_get_effective_priority (t))
		thread_yield();

	return tid;

err:
	if (thread_mlfqs)
		list_remove(&t->mlfqs.elem);
	
#ifdef USERPROG
	thread_exit_status_disown(t->exit_status);

	if (fd_stdin)
		free(fd_stdin);
	
	if (fd_stdout)
		free(fd_stdout);
#endif

	palloc_free_page(t);

	return TID_ERROR;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	list_push_back (&ready_list, &t->elem);
	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	
	if (thread_mlfqs) {
		/* Remove from global thread list */
		list_remove (&thread_current ()->mlfqs.elem);
	}

#ifdef USERPROG
	while(!list_empty(&thread_current ()->file_descriptors.list)) {
		struct list_elem* elem = list_pop_front(&thread_current ()->file_descriptors.list);
		struct file_descriptor* fd = list_entry(elem, struct file_descriptor, elem);
		file_descriptor_close(fd);
	}
#endif

	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable ();
	if (curr != idle_thread)
		list_push_back (&ready_list, &curr->elem);
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {
	if (thread_mlfqs)
		return;

	thread_current ()->priority = new_priority;

	if (
		!list_empty(&ready_list) &&
		thread_get_priority() < thread_get_effective_priority (list_entry(list_max(&ready_list, thread_less_priority, NULL), struct thread, elem))
	) {
		thread_yield();
	}
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	return thread_get_effective_priority (thread_current ());
}

int
thread_get_effective_priority (struct thread *thread) {
	if (thread_mlfqs) {
		return thread->priority;
	} else {
		return thread->priority < thread->donation.donation
			? thread->donation.donation
			: thread->priority;
	}
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) {
	ASSERT (thread_mlfqs);
	ASSERT (nice <= 20);
	ASSERT (-20 <= nice);

	thread_current ()->mlfqs.nice = nice;
	thread_current ()->priority = thread_calc_priority(thread_current ());

	if (
		!list_empty(&ready_list) &&
		thread_get_priority() < thread_get_effective_priority (list_entry(list_max(&ready_list, thread_less_priority, NULL), struct thread, elem))
	) {
		thread_yield();
	}
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	ASSERT (thread_mlfqs);

	return thread_current ()->mlfqs.nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	ASSERT(thread_mlfqs);
	return floater_to_int_round(floater_mul_int(load_avg, 100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	ASSERT(thread_mlfqs);
	return floater_to_int_round(floater_mul_int(thread_current ()->mlfqs.recent_cpu, 100));
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	
	if (!thread_mlfqs) {
		t->priority = priority;
		t->donation.donation = PRI_MIN;
		list_init(&t->donation.locks);
	}

#ifdef USERPROG
	list_init(&t->children);
	t->exit_status = NULL;

	list_init(&t->file_descriptors.list);
	t->file_descriptors.next_fd = 2;
	lock_init(&t->file_descriptors.next_fd_lock);

	t->executable_file = NULL;
#endif

	t->magic = THREAD_MAGIC;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else {
		struct thread *thread = list_entry (list_max (&ready_list, thread_less_priority, NULL), struct thread, elem);
		list_remove(&thread->elem);
		return thread;
	}
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used by the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}

#ifdef USERPROG
/* Create a thread_exit_status structure. */
bool
thread_exit_status_new(struct thread *thread) {
	struct thread_exit_status *exit_status = malloc(sizeof(struct thread_exit_status));
	if (!exit_status)
		return false;
	
	exit_status->pid = thread->tid;
	exit_status->exit_status = -1;
	exit_status->reference_count = 1;
	lock_init(&exit_status->reference_count_lock);
	sema_init(&exit_status->event, 0);

	thread->exit_status = exit_status;
	return true;
}

/* Increment reference count of the thread_exit_status. */
void
thread_exit_status_own(struct thread_exit_status *exit_status) {
	lock_acquire(&exit_status->reference_count_lock);
	exit_status->reference_count++;
	lock_release(&exit_status->reference_count_lock);
}

/* Wait until exit status is actually exit. */
int
thread_exit_status_wait(struct thread_exit_status *status) {
	ASSERT (thread_current ()->tid != status->pid);

	sema_down (&status->event);
	sema_up (&status->event);

	return status->exit_status;
}

/* Decrement reference count of the thread_exit_status. */
void thread_exit_status_disown(struct thread_exit_status *status) {
	bool shall_free;
	
	lock_acquire(&status->reference_count_lock);
	shall_free = !--status->reference_count;
	lock_release(&status->reference_count_lock);

	if (shall_free) {
		// Assume no one else using it.
		free(status);
	}
}

/* Finds the file descriptor associated with the fd. NULL if not found. */
struct file_descriptor* thread_find_file_descriptor(int fd) {
	struct list_elem *e;
	struct file_descriptor *file_descriptor;

	for (
		e = list_begin (&thread_current()->file_descriptors.list);
		e != list_end (&thread_current()->file_descriptors.list);
		e = list_next (e)
	) {
		file_descriptor = list_entry (e, struct file_descriptor, elem);
		if (file_descriptor->fd == fd)
			return file_descriptor;
	}

	return NULL;
}


struct file_descriptor* file_descriptor_open(const char *path) {
	struct file_descriptor *file_descriptor;

	file_descriptor = (struct file_descriptor *)malloc(sizeof(*file_descriptor));
	if (!file_descriptor)
		return NULL;
	
	file_descriptor->kind = FD_KIND_FILE;

	file_descriptor->file = file_rc_open(path);
	if (!file_descriptor->file) {
		free(file_descriptor);
		return NULL;
	}

	lock_acquire(&thread_current ()->file_descriptors.next_fd_lock);
	do {
		file_descriptor->fd = thread_current ()->file_descriptors.next_fd++;
	} while (thread_find_file_descriptor(file_descriptor->fd));	
	lock_release(&thread_current ()->file_descriptors.next_fd_lock);

	list_push_back(&thread_current ()->file_descriptors.list, &file_descriptor->elem);

	return file_descriptor;
}

struct file_descriptor* file_descriptor_reopen(struct file_descriptor* old) {
	struct file_descriptor *file_descriptor;

	ASSERT(old->kind == FD_KIND_FILE);

	file_descriptor = (struct file_descriptor *)malloc(sizeof(*file_descriptor));
	if (!file_descriptor)
		return NULL;
	
	file_descriptor->kind = FD_KIND_FILE;

	file_descriptor->file = file_rc_clone(old);
	if (!file_descriptor->file) {
		free(file_descriptor);
		return NULL;
	}

	lock_acquire(&thread_current ()->file_descriptors.next_fd_lock);
	do {
		file_descriptor->fd = thread_current ()->file_descriptors.next_fd++;
	} while (thread_find_file_descriptor(file_descriptor->fd));	
	lock_release(&thread_current ()->file_descriptors.next_fd_lock);

	list_push_back(&thread_current ()->file_descriptors.list, &file_descriptor->elem);

	return file_descriptor;
}

struct file_descriptor* file_descriptor_duplicate(struct file_descriptor* file_descriptor, int fd) {
	struct file_descriptor *clone, *old;

	if (file_descriptor->fd == fd) {
		return file_descriptor;
	}

	clone = (struct file_descriptor *)malloc(sizeof(*clone));
	if (!clone)
		return NULL;

	clone->kind = file_descriptor->kind;
	if (clone->kind == FD_KIND_FILE) {
		clone->file = file_descriptor->file;
		file_rc_own(clone->file);
	}

	if ((old = thread_find_file_descriptor (fd))) {
		file_descriptor_close(old);
	}

	clone->fd = fd;

	list_push_back(&thread_current ()->file_descriptors.list, &clone->elem);

	return clone;
}

void file_descriptor_close(struct file_descriptor *file_descriptor) {
	if (file_descriptor->kind == FD_KIND_FILE)
		file_rc_disown(file_descriptor->file);
	
	list_remove(&file_descriptor->elem);

	free(file_descriptor);
}

#endif

struct file_rc *file_rc_open(const char *path) {
	struct file_rc *rc = malloc(sizeof(struct file_rc));
	if (!rc)
		return NULL;

	lock_acquire(&io_lock);
	rc->file = filesys_open(path);
	lock_release(&io_lock);
	if (!rc->file) {
		free(rc);
		return NULL;
	}

	lock_init (&rc->reference_count_lock);
	rc->reference_count = 1;

	return rc;	
}

struct file_rc *file_rc_clone(struct file_rc *old_rc) {
	struct file_rc *rc = malloc(sizeof(struct file_rc));
	if (!rc)
		return NULL;

	rc->file = file_duplicate(old_rc->file);
	if (!rc->file) {
		free(rc);
		return NULL;
	}

	lock_init (&rc->reference_count_lock);
	rc->reference_count = 1;

	return rc;	
}

void file_rc_own(struct file_rc *rc) {
	lock_acquire(&rc->reference_count_lock);
	++rc->reference_count;
	lock_release(&rc->reference_count_lock);
}

void file_rc_disown(struct file_rc *rc) {
	ASSERT(rc->reference_count > 0);
	bool shall_free;

	lock_acquire(&rc->reference_count_lock);
	shall_free = !--rc->reference_count;
	lock_release(&rc->reference_count_lock);

	if (shall_free) {
		file_close(rc->file);
		free(rc);
	}
}