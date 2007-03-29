/* Python extension to interact with CRASH
   
  Time-stamp: <07/03/27 11:56:33 alexs>

  Copyright (C) 2006 Alex Sidorenko <asid@hp.com>
  Copyright (C) 2006 Hewlett-Packard Co., All rights reserved.
 
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
*/

#include <Python.h>

#include <unistd.h>
#include <stdlib.h>
#include <sys/times.h>

#include <libgen.h>


#include "defs.h"    /* From the crash source top-level directory */

int debug = 0;

static const char *crash_version = "0.3";

/* Initialize the crashmodule stuff */
void initcrash(const char *) ;


/* This function is called when we do sys.exit(n). The standard Py_Exit is
   defines in Python sourcefile Modules/pythonrun.c and it does Py_Finalize
   and exit(). This will destroy the intepreter and terminate crash.
   We don't want our extensions to terminate crash, so we link-in our own
   version of this function. This works on IA32 but I am not sure about other
   architectures
*/

#if !defined(STATICBUILD)
PyAPI_DATA(int) Py_NoSiteFlag;

void
Py_Exit(int sts) {
  if (sts)
    printf("sys.exit(%d)\n", sts);
}
#endif


// The next pair of functions makes it possible to run some tasks
// just before we start executing 'epython ...' and before we return
// to 'crash' prompt

// Entering
static void
call_sys_enterepython(void)
{
        PyObject *enterfunc = PySys_GetObject("enterepython");

        if (enterfunc) {
                PyObject *res;
                Py_INCREF(enterfunc);
                //PySys_SetObject("enterepython", (PyObject *)NULL);
                res = PyEval_CallObject(enterfunc, (PyObject *)NULL);
                if (res == NULL) {
                        if (!PyErr_ExceptionMatches(PyExc_SystemExit)) {
                                PySys_WriteStderr("Error in sys.enterepython:\n");
                        }
                        PyErr_Print();
                }
                Py_DECREF(enterfunc);
        }

        if (Py_FlushLine())
                PyErr_Clear();
}

// Exiting
static void
call_sys_exitepython(void)
{
        PyObject *exitfunc = PySys_GetObject("exitepython");

        if (exitfunc) {
                PyObject *res;
                Py_INCREF(exitfunc);
                //PySys_SetObject("exitepython", (PyObject *)NULL);
                res = PyEval_CallObject(exitfunc, (PyObject *)NULL);
                if (res == NULL) {
                        if (!PyErr_ExceptionMatches(PyExc_SystemExit)) {
                                PySys_WriteStderr("Error in sys.exitepython:\n");
                        }
                        PyErr_Print();
                }
                Py_DECREF(exitfunc);
        }

        if (Py_FlushLine())
                PyErr_Clear();
}

void cmd_epython();     /* Declare the commands and their help data. */
char *help_epython[];

static struct command_table_entry command_table[] = {
        "epython", cmd_epython, help_epython, 0,           /* One or more commands, */
        NULL,                                     /* terminated by NULL, */
};


_init() /* Register the command set. */
{ 
        register_extension(command_table);
	if (getenv("PYKDUMPDEBUG"))
	  debug = 1;
}
 
/* 
 *  The _fini() function is called if the shared object is unloaded. 
 *  If desired, perform any cleanups here. 
 */
_fini() { }

static int py_fclose(FILE *fp) {
  return 0;
}

/* 
 *  Arguments are passed to the command functions in the global args[argcnt]
 *  array.  See getopt(3) for info on dash arguments.  Check out defs.h and
 *  other crash commands for usage of the myriad of utility routines available
 *  to accomplish what your task.
 */

#if defined(X86)
const char *PYHOME = "Python32";
#endif

#if defined(X86_64)
const char *PYHOME = "Python64";
#endif

#define BUFLEN 1024
void
cmd_epython()
{
  FILE *scriptfp;
  PyObject *crashfp;
  static PyObject *sysm = NULL, *crashm = NULL;
  PyObject *syspath;
  static long TICKSPS;
  struct tms t1, t2;
  const char *pypath;
  char buffer[BUFLEN];
  
  scriptfp = fopen(args[1], "r");
  /* No need to do anything if the file does not exist */
  if (scriptfp == NULL) {
    fprintf(fp, " Cannot open the file <%s>\n", args[1]);
    return;
  }
  if (!Py_IsInitialized()) {
    // A hack - add a correct PATH if needed
    pypath = getenv("PYTHONPATH");
#if defined(STATICBUILD)
    Py_NoSiteFlag = 1;
    if (pypath) {
      snprintf(buffer, BUFLEN, "PYTHONHOME=%s/%s", pypath, PYHOME);
      putenv(buffer);
    } else if (argcnt > 1) {
      // Use the path of the 1st Python script executed
      char *prog, *pdir;
      readlink(args[1], buffer, BUFLEN);
      prog = strdup(buffer);
      pdir = dirname(prog);
      snprintf(buffer, BUFLEN, "PYTHONHOME=%s/%s", pdir, PYHOME);
      putenv(buffer);
      free(prog);
    }
#endif
    if (debug)
      fprintf(fp, "     *** Initializing Embedded Python %s ***\n", crash_version);
    Py_Initialize();
    PyEval_InitThreads();
    initcrash(crash_version);
    sysm = PyImport_ImportModule("sys");
    crashm = PyImport_ImportModule("crash");
    if (debug)
      PyRun_SimpleString("import sys;print sys.path");
    
    if (0) {
      snprintf(buffer, BUFLEN, "import sys;sys.path.insert(0, \"%s\")", pypath);
      //printf("CMD=%s\n", buffer);
      PyRun_SimpleString(buffer);
    }
    // For static build, set PYTHONHOME to the first directory in sys.path
  
    TICKSPS = sysconf(_SC_CLK_TCK);
  }
  times(&t1);
  // Connect sys.stdout to fp
  crashfp = PyFile_FromFile(fp, "<crash fp>", "w", py_fclose);

  // We should add handling exceptions here to prevent 'crash' from exiting
  if (argcnt > 1) {
    PyRun_SimpleString("import sys");
    PySys_SetArgv(argcnt-1, args+1);
    PyModule_AddObject(sysm, "stdout", crashfp);

    /* The function will be available only on the 2nd and further invocations
     of epython as it is normally defined in API.py which is not loaded yet */
    call_sys_enterepython();
    /* This is where we run the real user-provided script */
    PyRun_SimpleFile(scriptfp, args[1]);
    
    // PyRun_SimpleFile inserts the path of command every time it is executed
    // so it's better to remove it here
    PyRun_SimpleString("del sys.path[0]");
  } else {
    // No arguments passed
    PyRun_SimpleString("import sys; print sys.path");
  }
  // Run epython exitfuncs (if registered)
  call_sys_exitepython();

  /* 
  times(&t2);
  fprintf(fp, "  -- %6.2fs --\n",
	  ((double)(t2.tms_utime-t1.tms_utime))/TICKSPS);
  fflush(fp);

  */
    
  // Destroy - unfortunately this sometimes leads to segfaults, better not to
  // not it here
  //Py_DECREF(crashfp);
  //Py_Finalize();
}

 
char *help_epython[] = {
        "epython",                        /* command name */
        "invokes embedded Python interpreter",   /* short description */
        "program.py arg ...",	/* argument synopsis, or " " if none */
 
        "  This command invokes embedded Python.",
        "\nEXAMPLE",
        "  Output information about net devices:\n",
        "    crash> epython netdev.py",
        NULL
};


