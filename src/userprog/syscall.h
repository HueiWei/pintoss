#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdio.h>
#include "lib/kernel/list.h"
#include "threads/thread.h"

void syscall_init (void);

// Extra function
bool check_pointer (void * ptr);
struct file_desc * get_file(int);
void getArgs (void* esp, int* arg, int count);

/* System Calls */
void halt(void);
void exit(int status);
tid_t exec (const char * cmd_line);
int wait(tid_t);
bool create (const char *file, unsigned initial_size);
bool remove(const char *file);
int open (const char * file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd,const void *buffer, unsigned size);
void seek(int fd,unsigned position);
unsigned tell (int fd);
void close (int fd);

/* A lock for access to filesys
   Since filesys is not yet concurrent */
struct lock filesys_lock;

// Structure to describe files
struct file_desc
{
  struct file * fp;
  int fd;
  struct list_elem elem;
};




#endif /* userprog/syscall.h */