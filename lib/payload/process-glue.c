#include "frida-payload.h"

#ifdef HAVE_WINDOWS
# define VC_EXTRALEAN
# include <windows.h>
#else
# include <pthread.h>
# include <signal.h>
# include <unistd.h>
#endif
#ifdef HAVE_DARWIN
# include <limits.h>
# include <mach-o/dyld.h>
#endif

guint
frida_get_process_id (void)
{
#ifdef HAVE_WINDOWS
  return GetCurrentProcessId ();
#else
  return getpid ();
#endif
}

gpointer
frida_get_current_native_thread (void)
{
#ifdef HAVE_WINDOWS
  HANDLE thread_handle;
  if (DuplicateHandle (GetCurrentProcess (), GetCurrentThread (), GetCurrentProcess (),
      &thread_handle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
    return thread_handle;
  }

  g_assert_not_reached ();
#else
  return (gpointer) pthread_self ();
#endif
}

void
frida_join_native_thread (gpointer thread)
{
#ifdef HAVE_WINDOWS
  HANDLE thread_handle = (HANDLE) thread;

  WaitForSingleObject (thread_handle, INFINITE);
  CloseHandle (thread_handle);
#else
  pthread_join ((pthread_t) thread, NULL);
#endif
}

void
frida_kill_process (guint pid)
{
#ifdef HAVE_WINDOWS
  HANDLE process;

  process = OpenProcess (PROCESS_TERMINATE, FALSE, pid);
  if (process == NULL)
    return;

  TerminateProcess (process, 1);

  CloseHandle (process);
#else
  kill (pid, SIGKILL);
#endif
}

gchar *
frida_try_get_executable_path (void)
{
#ifdef HAVE_DARWIN
  uint32_t buf_size;
  gchar * buf;

  buf_size = PATH_MAX;

  do
  {
    buf = g_malloc (buf_size);
    if (_NSGetExecutablePath (buf, &buf_size) == 0)
      return buf;

    g_free (buf);
  }
  while (TRUE);
#elif HAVE_LINUX
  return g_file_read_link ("/proc/self/exe", NULL);
#else
  return NULL;
#endif
}
