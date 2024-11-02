#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "filesys/file.h"
#include "devices/input.h"

static struct lock io_lock;

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void halt(void);
void exit(int status);
tid_t fork(const char *thread_name, struct intr_frame *f);
int exec(const char *cmd_line);
int wait(tid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

void validate_buffer(const void* ptr, size_t size);
void validate_string(const char* str);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	
	lock_init(&io_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	const uint64_t syscall_number = f->R.rax;
	const uint64_t args[] = { f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r9, f->R.r8 };
	uint64_t status = 0;

	switch (syscall_number) {
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(args[0]);
		break;
	case SYS_FORK:
		status = fork(args[0], f);
		break;
	case SYS_EXEC:
		status = exec(args[0]);
		break;
	case SYS_WAIT:
		status = wait(args[0]);
		break;
	case SYS_CREATE:
		status = create(args[0], args[1]);
		break;
	case SYS_REMOVE:
		status = remove(args[0]);
		break;
	case SYS_OPEN:
		status = open(args[0]);
		break;
	case SYS_FILESIZE:
		status = filesize(args[0]);
		break;
	case SYS_READ:
		status = read(args[0], args[1], args[2]);
		break;
	case SYS_WRITE:
		status = write(args[0], args[1], args[2]);
		break;
	case SYS_SEEK:
		seek(args[0], args[1]);
		break;
	case SYS_TELL:
		status = tell(args[0]);
		break;
	case SYS_CLOSE:
		close(args[0]);
		break;
	default:
		status = -1;
		break;
	}

	f->R.rax = status;
}

/* Reads a byte at user virtual address UADDR.
 * UADDR must be below KERN_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. */
static int64_t
get_user (const uint8_t *uaddr) {
    int64_t result;
    __asm __volatile (
    "movabsq $done_get, %0\n"
    "movzbq %1, %0\n"
    "done_get:\n"
    : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
 * UDST must be below KERN_BASE.
 * Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte) {
    int64_t error_code;
    __asm __volatile (
    "movabsq $done_put, %0\n"
    "movb %b2, %1\n"
    "done_put:\n"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}

void
halt (void) {
	power_off();
}

void
exit (int status) {
	printf ("%s: exit(%d)\n", thread_current ()->name, status);

	struct thread_exit_status* exit_status = thread_current ()->exit_status;
	if (exit_status)
		exit_status->exit_status = status;
	
	thread_exit ();
}

tid_t
fork (const char *thread_name, struct intr_frame *f) {
	validate_string(thread_name);

	return process_fork (thread_name, f);
}

int
exec (const char *cmd_line) {
	validate_string(cmd_line);

	char *cmd_line_copy = palloc_get_page (0);
	if (cmd_line_copy == NULL)
		return -1;

	strlcpy (cmd_line_copy, cmd_line, PGSIZE);

	if (process_exec(cmd_line_copy) < 0)
		exit(-1);
	
	NOT_REACHED()
	return 0;
}

int
wait (tid_t pid) {
	return process_wait (pid);
}

bool
create (const char *file, unsigned initial_size) {
	validate_string(file);

	return filesys_create(file, initial_size);
}

bool
remove (const char *file) {
	validate_string(file);

	return filesys_remove(file);
}

int
open (const char *file) {
	struct file_descriptor *file_descriptor;

	validate_string(file);

	file_descriptor = (struct file_descriptor *)malloc(sizeof(*file_descriptor));
	if (!file_descriptor)
		return -1;

	lock_acquire(&io_lock);	
	file_descriptor->file = filesys_open(file);
	lock_release(&io_lock);

	if (!file_descriptor->file) {
		free(file_descriptor);
		return -1;
	}

	lock_acquire(&thread_current ()->file_descriptors.next_fd_lock);
	file_descriptor->fd = thread_current ()->file_descriptors.next_fd++;
	lock_release(&thread_current ()->file_descriptors.next_fd_lock);

	list_push_back(&thread_current ()->file_descriptors.list, &file_descriptor->elem);

	return file_descriptor->fd;
}

int
filesize (int fd) {
	struct file_descriptor* file_descriptor = thread_find_file_descriptor(fd);
	if (!file_descriptor)
		return -1;
	
	int len;
	lock_acquire(&io_lock);
	len = file_length(file_descriptor->file);
	lock_release(&io_lock);

	return len;
}

int
read (int fd, void *buffer, unsigned size) {
	validate_buffer(buffer, size);

	if (fd == 0) {
		for (size_t i = 0; i < size; i++)
		{
			((uint8_t*) buffer)[i] = input_getc();
		}
		return size;		
	}

	struct file_descriptor* file_descriptor = thread_find_file_descriptor(fd);
	if (!file_descriptor)
		return -1;
	
	unsigned size_read;
	lock_acquire(&io_lock);
	size_read = file_read(file_descriptor->file, buffer, size);
	lock_release(&io_lock);

	return size_read;

}

int
write (int fd, const void *buffer, unsigned size) {
	validate_buffer(buffer, size);

	if (fd == 1) {
		putbuf(buffer, size);
		return size;		
	}

	struct file_descriptor* file_descriptor = thread_find_file_descriptor(fd);
	if (!file_descriptor)
		return -1;
	
	unsigned size_wrote;
	lock_acquire(&io_lock);
	size_wrote = file_write(file_descriptor->file, buffer, size);
	lock_release(&io_lock);

	return size_wrote;
}

void
seek (int fd, unsigned position) {
	struct file_descriptor* file_descriptor = thread_find_file_descriptor(fd);
	if (!file_descriptor)
		return;
	
	lock_acquire(&io_lock);
	file_seek(file_descriptor->file, position);
	lock_release(&io_lock);
}

unsigned
tell (int fd) {
	struct file_descriptor* file_descriptor = thread_find_file_descriptor(fd);
	if (!file_descriptor)
		return 0;
	
	unsigned pos;
	lock_acquire(&io_lock);
	pos = file_tell(file_descriptor->file);
	lock_release(&io_lock);

	return pos;
}

void
close (int fd) {
	struct file_descriptor* file_descriptor = thread_find_file_descriptor(fd);
	if (!file_descriptor)
		return;

	lock_acquire(&io_lock);
	file_close(file_descriptor->file);
	lock_release(&io_lock);

	list_remove(&file_descriptor->elem);
	free(file_descriptor);
}

void
validate_string(const char* str) {
	for (const char *i = str; is_user_vaddr(i); i++) {
		int64_t ubyte = get_user((const uint8_t *)i);

		if (ubyte < 0)
			break;
		else if (ubyte == 0)
			return;
	}

	exit(-1);
}

void
validate_buffer (const void *buf, size_t size) {
	const uint8_t *i;

	for (i = buf; i < (uint8_t *)buf + size && is_user_vaddr(i) && get_user(i) >= 0; i++);

	if (i < (uint8_t *)buf + size) {
		exit(-1);
	}
}