#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "pagedir.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  // Init lock
  lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  
  // If the condition pointer is invalid, exit
  if(!check_pointer ((const void *) f->esp)) {
    exit(-1);
  }

  //Stores the parameters passed to the syscall function
  int arg[3];
  
  int syscall_number = * (int *)f->esp;
  

  

  //After confirming the system call number, we will pass arguments to the system functions
  
  // arg[0]: The first parameter
  // arg[1]: The second parameter
  // arg[2]: The third parameter 
  
  //Invalid System Call Number, we exit

  switch (syscall_number)
  {
    case SYS_HALT:
      halt();
      break;
		
		case SYS_EXIT:
      getArgs(f->esp, &arg[0], 1);
	    exit(arg[0]);
	    break;

    case SYS_EXEC:
      getArgs(f->esp, &arg[0], 1);
	    f->eax = exec((const char *) arg[0]); 
	    break;
    
		case SYS_WAIT:
      getArgs(f->esp, &arg[0], 1);
	    f->eax = wait(arg[0]);
	    break;
    
    case SYS_CREATE:
      getArgs(f->esp, &arg[0], 2);
	    f->eax = create((const char *)arg[0], (unsigned) arg[1]);
	    break;
    case SYS_REMOVE:
      getArgs(f->esp, &arg[0], 1);
	    f->eax = remove((const char *) arg[0]);
	    break;
    
    case SYS_OPEN:
      getArgs(f->esp, &arg[0], 1);
	    f->eax = open((const char *) arg[0]);
	    break; 	
   
    case SYS_FILESIZE:
      getArgs(f->esp, &arg[0], 1);
	    f->eax = filesize(arg[0]);
	    break;

    case SYS_READ:
      getArgs(f->esp, &arg[0], 3);
      f->eax = read(arg[0], (void *) arg[1], (unsigned) arg[2]);
	    break;
		
		case SYS_WRITE:
      getArgs(f->esp, &arg[0], 3);
	    f->eax = write(arg[0], (const void *) arg[1],(unsigned) arg[2]);
	    break;
    case SYS_SEEK:
      getArgs(f->esp, &arg[0], 2);
	    seek(arg[0], (unsigned) arg[1]);
	    break;
    
    case SYS_TELL:
      getArgs(f->esp, &arg[0], 1);
	    f->eax = tell(arg[0]);
	    break;
		
		case SYS_CLOSE:
      getArgs(f->esp, &arg[0], 1);
	    close(arg[0]);
	    break;
    
		default:
      hex_dump(f->esp,f->esp,64,true);
      printf("Invalid System Call number\n");
			exit(-1);   
			break;
  }

}

// Shutdown Pintos
void halt (void)
{
  shutdown_power_off();
}

// Terminates the current user program, returning status to the kernel
void exit (int status)
{
  struct thread * parent = thread_current()->parent;
  
  // Updating the exit code of current thread
  thread_current()->exit_code = status;
  if (!list_empty(&parent->children))
  {
    
    
    // If the thread to be exited is a child of another thread,
    // we update the ret_val in the parent's relevant struct
    // i.e. children list's element for the exiting thread
    // We wake up the parent thread if it is waiting for this thread's
    // completion
    

    // get_child returns parents relevant struct 
    struct child * child = get_child(thread_current()->tid,parent);

    if (child!=NULL)
    {
      child->ret_val=status;
      child->used = 1;
      
      // Waking up the parent thread if it is waiting 
      // on the current thread 
      if (thread_current()->parent->waiton_child 
              == thread_current()->tid)
        sema_up(&thread_current()->parent->child_sem);
        
    }
  }
  
  thread_exit();
}

//Runs the executable whose name is given in cmd_line,
//passing any given arguments, and returns the new process's program id (tid_t)
tid_t exec (const char * cmd_line)
{
  lock_acquire(&filesys_lock);
  tid_t tid = process_execute(cmd_line);
  lock_release(&filesys_lock);
  return tid;
}

// Waits for a child process pid and retrieves the child's exit status.
int wait(tid_t id)
{
  tid_t tid = process_wait(id);
  return tid;
}

// Creates a new file called file initially initial_size bytes in size, does not open it
bool create (const char * file, unsigned initial_size)
{
  lock_acquire(&filesys_lock);

  if (file == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }
  //Creates a file named file with the given initial_size
  //Returns true if successful, false otherwise 
  //when using filesys function
  int isSuccess = filesys_create(file,initial_size);
  lock_release(&filesys_lock);
  
  return isSuccess;
}

// A file may be removed regardless of whether it is open or closed, and removing an open file does not close it
bool remove (const char * file)
{
  lock_acquire(&filesys_lock);
  if (file == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }
  // Deletes the file named file
  // Returns true if successful, false on failure
  // when using filesys function
  bool isSuccess = filesys_remove(file);
  lock_release(&filesys_lock);

  return isSuccess;
}

// Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could not be opened.
int open (const char * file)
{
  lock_acquire(&filesys_lock);

  // Opens the file with the given "file"
  // Returns the new file if successful or a null pointer
  // when using filesys function
  struct file * fp = filesys_open (file);
  lock_release(&filesys_lock);
  
  if (fp == NULL) 
    return -1;
  
  struct file_desc * fdElement = malloc (sizeof(struct file_desc));

  //the fd attribute stores the sequence number
  // of the file in the process running it
  fdElement->fd = ++thread_current()->fd_count;
  fdElement->fp = fp;
  list_push_front(&thread_current()->file_list,&fdElement->elem);
  
  return fdElement->fd;
}

// Returns the size, in bytes, of the file open as fd.
int filesize (int fd)
{
  //Get the file descriptor of the sorted file fd in the current process 
  //and save it in the variable fdElement
  struct file_desc * fdElement = get_file(fd);
  
  // Return -1 if fdElement does not exist 
  lock_acquire(&filesys_lock);
  if (fdElement == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }
  
  // Return size from the file using filesys function
  int size = file_length(fdElement->fp); 
  lock_release(&filesys_lock);
  return size;
}

// Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read 
int read (int fd, void * buffer, unsigned length)
{
  int len =0;
  
  // If fd == 0, reads from keyboard using input_getc()
  if (fd == STDIN_FILENO)
  { 
    while (len < length)
    {
      *((char *)buffer+len) = input_getc();
      len++;
    }
    return len;
  }

  // For an fd other than 0, retrieve file_desc elem
  struct file_desc * fdElement = get_file(fd);
  
  lock_acquire(&filesys_lock);
  if (fdElement == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }
  // Read from the file using filesys function
  len = file_read(fdElement->fp,buffer,length);
  lock_release(&filesys_lock);
  return len;
}

// Writes size bytes from buffer to the open file fd.
// Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
int write (int fd, const void *buffer, unsigned length)
{
  // if fd == 1, write to standard output
  if (fd == STDOUT_FILENO)
  {
    putbuf(buffer,length);
    return length;
  }
  
  // For fd other than 1, retrieve file_desc elem
  struct file_desc * fdElement = get_file(fd);
  
  lock_acquire(&filesys_lock);
  if (fdElement == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }
  // write to the file using filesys function
  int bytes = file_write(fdElement->fp,buffer,length);
  lock_release(&filesys_lock);
  return bytes;
}

// Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file.
void seek (int fd, unsigned position)
{
  // //Get the file descriptor of the sorted file fd in the current process 
  //and save it in the variable fdElement
  struct file_desc * fdElement = get_file(fd);

  
  lock_acquire(&filesys_lock);
  if (fdElement == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }
  file_seek(fdElement->fp,position);
  lock_release(&filesys_lock);
}

// Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file.
unsigned tell (int fd)
{
  struct file_desc * fdElement = get_file(fd);

  lock_acquire(&filesys_lock);
  if (fdElement == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }
  unsigned position = file_tell (fdElement->fp);
  lock_release(&filesys_lock);
  return position;
}

// Closes file descriptor fd.
// Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one.

void close (int fd)
{
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
    return;
  
  //Get the file descriptor of the sorted file fd in the current process 
  //and save it in the variable fdElement
  struct file_desc * fdElement = get_file(fd);

  
  lock_acquire(&filesys_lock);
  if (fdElement == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }
  // Closing file using file sys function
  file_close(fdElement->fp);
  lock_release(&filesys_lock);

  // Remove file and freeing memory
  list_remove(&fdElement->elem);
  free(fdElement);

}

// Check the validity of a user-supplied pointer
bool check_pointer(void * ptr)
{
  return (ptr != NULL &&
    is_user_vaddr(ptr) && 
    pagedir_get_page(thread_current()->pagedir,ptr)!=NULL);
}

// Pass the argument of the syscall function to the array arg 
void getArgs (void *esp, int *arg, int count) {
  int i = 0;
  while (i < count) {
    int *stackPointer = (int *)esp+(i+1);
    if (!check_pointer((const void *) stackPointer)) {
      exit(-1);
    }
    arg[i] = *stackPointer;
    i++;
  }
}

// Get file numbered as fd of running process
struct file_desc * get_file (int fd)
{
  struct thread * curr = thread_current();
  struct list_elem * e;

  for (e=list_begin(&curr->file_list);
    e != list_end (&curr->file_list); e = list_next(e))
  {
    struct file_desc * fdElement = list_entry(e, struct file_desc,elem);
    if (fdElement->fd == fd)
      return fdElement;
  } 

  return NULL;
}