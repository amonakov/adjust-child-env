/*
   Copyright (C) 2013 Samsung Electronics
   Written by Alexander Monakov, ISP RAS

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#ifdef __ANDROID__
#include <asm/user.h>
#include <android/log.h>
#else
#include <sys/user.h>
#endif

static void
print_log(const char *format, ...)
{
  int save_errno = errno;
  va_list arguments;
  va_start(arguments, format);
#ifdef ANDROID
  __android_log_vprint(ANDROID_LOG_DEBUG, "adjust-env", format, arguments);
#else
  fprintf(stderr, "adjust-env: ");
  vfprintf(stderr, format, arguments);
#endif
  va_end(arguments);
  errno = save_errno;
}

static void
usage(const char *argv0)
{
  fprintf(stderr, "Usage: %1$s <pid> <exe> <env>\n"
	  "\n"
	  "Attach to process with PID <pid> and follow forks.\n"
	  "When one of the forked children is about to execve to <exe>,\n"
	  "add <env> to its environment and detach every traced process.\n"
	  "\n"
	  "Example (inject GL tracing library into DalvikVM on Android):\n"
	  "%1$s 1 /system/bin/app_process LD_PRELOAD=/data/egltrace.so\n",
	  argv0);
  exit(1);
}

#if defined(__x86_64__)
#define REG_SYSCALLNO orig_rax
#define REG_FIRST_ARG rdi
#define REG_THIRD_ARG rdx
#define REG_STACK_PTR rsp
#elif defined(__i386__)
#define REG_SYSCALLNO orig_eax
#define REG_FIRST_ARG ebx
#define REG_THIRD_ARG edx
#define REG_STACK_PTR esp
#elif defined(__arm__)
#define REG_SYSCALLNO ARM_r7
#define REG_FIRST_ARG ARM_ORIG_r0
#define REG_THIRD_ARG ARM_r2
#define REG_STACK_PTR ARM_sp
#else
#error Unsupported architecture
#endif

static long
xptrace(int r, pid_t p, void *a, void *d)
{
  assert(!errno);
  long ret = ptrace(r, p, a, d);
  if (errno)
    {
      print_log("ptrace: %s\n", strerror(errno));
      exit(1);
    }
  return ret;
}

static pid_t
xwaitpid(pid_t pid, int *status, int options)
{
  assert(!errno);
  pid_t ret = waitpid(pid, status, options);
  if (errno)
    {
      print_log("waitpid: %s\n", strerror(errno));
      exit(1);
    }
  return ret;
}

#define PEEK_REG(pid, reg)      \
  xptrace(PTRACE_PEEKUSER, pid, \
          (void*)offsetof(struct user, regs.reg), NULL)

#define PEEK_DATA(pid, ptr) \
  xptrace(PTRACE_PEEKDATA, pid, (void*)(ptr), NULL)

#define POKE_REG(pid, reg, val) \
  xptrace(PTRACE_POKEUSER, pid, \
          (void*)offsetof(struct user, regs.reg), (void*)(val))

#define POKE_DATA(pid, ptr, val) \
  xptrace(PTRACE_POKEDATA, pid, (void*)(ptr), (void*)(val))


static long
get_syscallno(pid_t pid)
{
  return PEEK_REG(pid, REG_SYSCALLNO);
}

static bool
match_exe(pid_t pid, const char *exe)
{
  unsigned long fileptr = PEEK_REG(pid, REG_FIRST_ARG);
  int len = strlen(exe);
  unsigned long offs, part;

  do {
      offs = fileptr & (sizeof(long) - 1);
      fileptr -= offs;
      part = PEEK_DATA(pid, fileptr);
      if (strncmp(exe, ((char*)&part) + offs, sizeof(long) - offs))
	return false;
      fileptr += sizeof(long);
      exe += sizeof(long) - offs;
      len -= sizeof(long) - offs;
  } while (len > 0);

  return true;
}

static void
adjust_env(pid_t pid, const char *newenv)
{
  char **envptr = (char **)PEEK_REG(pid, REG_THIRD_ARG);

  int envlen = 0;
  unsigned long envelt;
  do {
    envelt = PEEK_DATA(pid, envptr + envlen);
    envlen++;
  } while (envelt);

  long stackptr = PEEK_REG(pid, REG_STACK_PTR);

  stackptr -= (envlen + 1) * sizeof(char*);
  stackptr -= strlen(newenv) + 1;
  stackptr &= ~(sizeof(long) - 1);

  POKE_REG(pid, REG_THIRD_ARG, stackptr);

  for (envlen--; envlen; envlen--)
    {
      POKE_DATA(pid, stackptr, PEEK_DATA(pid, envptr));
      envptr++;
      stackptr += sizeof(char*);
    }
  POKE_DATA(pid, stackptr, stackptr + 2*sizeof(char*));
  stackptr += sizeof(char*);
  POKE_DATA(pid, stackptr, NULL);
  stackptr += sizeof(char*);

  for (;;)
    {
      long part;
      memcpy(&part, newenv, sizeof(long));
      POKE_DATA(pid, stackptr, part);
      if (memchr(newenv, 0, sizeof(long)))
	break;
      stackptr += sizeof(long);
      newenv += sizeof(long);
    }
}

int main(int argc, const char *argv[])
{
  if (argc != 4)
    usage(argv[0]);
  pid_t pid = atoi(argv[1]), mainpid = pid;
  int n_tracked = 1;
  errno = 0;
  xptrace(PTRACE_ATTACH, pid, NULL, NULL);
  print_log("attaching to %d\n", pid);
  xwaitpid(pid, NULL, __WALL);
  xptrace(PTRACE_SETOPTIONS, pid, NULL, (void*)PTRACE_O_TRACEFORK);
  xptrace(PTRACE_CONT, pid, NULL, NULL);

  int status;
  for (;;)
    {
      pid = xwaitpid(-1, &status, __WALL);
      if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
	{
	  if (pid == mainpid)
	    {
	      if (status & (PTRACE_EVENT_FORK << 16))
		{
		  pid_t child;
		  xptrace(PTRACE_GETEVENTMSG, pid, NULL, (void*)&child);
		  xwaitpid(child, NULL, __WALL);
		  xptrace(PTRACE_SYSCALL, child, NULL, NULL);
		  print_log("attached to child %d\n", child);
		  n_tracked++;
		}
	      xptrace(PTRACE_CONT, pid, NULL, NULL);
	    }
	  else if (get_syscallno(pid) == __NR_execve)
	    {
	      if (match_exe(pid, argv[2]))
		{
		  adjust_env(pid, argv[3]);
		  xptrace(PTRACE_DETACH, pid, NULL, (void*)SIGCONT);
		  print_log("adjusted env and detached from execing %d\n", pid);
		  n_tracked--;
		  break;
		}
	      else
		{
		  xptrace(PTRACE_DETACH, pid, NULL, (void*)SIGCONT);
		  print_log("detached from execing %d\n", pid);
		  n_tracked--;
		}
	    }
	  else
	    xptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	}
      else if (!WIFEXITED(status))
	xptrace(pid == mainpid ? PTRACE_CONT : PTRACE_SYSCALL, pid, NULL,
		(void*)(long)WSTOPSIG(status));
      else
	{
	  print_log("tracked process %d has exited\n", pid);
	  n_tracked--;
	}
    }

  print_log("detaching remaining %d processes\n", n_tracked);
  kill(mainpid, SIGTRAP);
  while (n_tracked)
    {
      errno = 0;
      pid = waitpid(-1, &status, __WALL);
      if (pid <= 0)
	break;
      if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
	xptrace(PTRACE_DETACH, pid, NULL, (void*)SIGCONT);
      else if (!WIFEXITED(status))
	xptrace(PTRACE_DETACH, pid, NULL, (void*)(long)WSTOPSIG(status));
      n_tracked--;
    }
  print_log("exiting\n");
  return 0;
}
