/* Python extension to interact with CRASH
   

  Copyright (C) 2006-2010 Alex Sidorenko <asid@hp.com>
  Copyright (C) 2006-2010 Hewlett-Packard Co., All rights reserved.
 
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
#include <stdlib.h>

#include "defs.h"    /* From the crash source top-level directory */

#include "pykdump.h"

/* Unfortuntely, we cannot replace that internal header with a nice <endian.h>
   as we need __cpu_to_le32
*/
#include <asm/byteorder.h>
//#include <endian.h>

// for FD_ISSET
#include <sys/select.h>

extern struct extension_table *epython_curext;
extern int epython_execute_prog(int argc, char *argv[], int);

extern int debug;
static jmp_buf alarm_env;
static jmp_buf copy_pc_env;

/* We save the version of crash against which we build */
const char *build_crash_version = CRASHVERS;

/* crash exceptions */
PyObject *crashError;

static PyObject *m, *d;		/* Our module object and its dictionary */

/* Default memory time for readmem() */
static int default_mtype = KVADDR;

static PyObject *
py_crash_symbol_exists(PyObject *self, PyObject *args) {
  char *varname;
  int val;
     
  if (!PyArg_ParseTuple(args, "s", &varname)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }

  val = symbol_exists(varname);
  return Py_BuildValue("i", val);
}

static PyObject *
py_crash_struct_size(PyObject *self, PyObject *args) {
  char *varname;
  long val;
     
  if (!PyArg_ParseTuple(args, "s", &varname)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }

  val = STRUCT_SIZE(varname);
  return Py_BuildValue("l", val);
}

static PyObject *
py_crash_union_size(PyObject *self, PyObject *args) {
  char *varname;
  long val;
     
  if (!PyArg_ParseTuple(args, "s", &varname)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }

  val = UNION_SIZE(varname);
  return Py_BuildValue("l", val);
}

static PyObject *
py_crash_member_size(PyObject *self, PyObject *args) {
  char *name, *member;
  long val;
     
  if (!PyArg_ParseTuple(args, "ss", &name, &member)) {
    PyErr_SetString(crashError, "invalid parameter(s) type"); \
    return NULL;
  }

  val = MEMBER_SIZE(name, member);
  return Py_BuildValue("l", val);
}

static PyObject *
py_crash_member_offset(PyObject *self, PyObject *args) {
  char *name, *member;
  long val;
     
  if (!PyArg_ParseTuple(args, "ss", &name, &member)) {
    PyErr_SetString(crashError, "invalid parameter(s) type"); \
    return NULL;
  }

  val = MEMBER_OFFSET(name, member);
  return Py_BuildValue("l", val);
}

static PyObject *
py_crash_get_symbol_type(PyObject *self, PyObject *args) {
  char *name, *member = NULL;
  int val;
  struct gnu_request req;
     
  if (!PyArg_ParseTuple(args, "s|s", &name, &member)) {
    PyErr_SetString(crashError, "invalid parameter(s) type"); \
    return NULL;
  }

  printf("name=%s, member=%s\n", name, member);
  val = get_symbol_type(name, member, &req);
  // BUG
  printf("val=%d, length=%d, name=%s, typename=%s, tagname=%s\n",
	 val, (int)req.length, req.name, req.typename, req.tagname);
  
  return Py_BuildValue("i", val);
}

static PyObject *
py_get_GDB_output(PyObject *self, PyObject *args) {
  char *cmd;
  char buf[BUFSIZE];

  PyObject *out = PyString_FromString("");
  PyObject *newpart;
     
  if (!PyArg_ParseTuple(args, "s", &cmd)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }
  if (debug > 1)
    printf("exec_gdb_command %s\n", cmd);

  // Send command to GDB and get its text output

  open_tmpfile();
  if (!gdb_pass_through(cmd, NULL, GNU_RETURN_ON_ERROR)) {
    close_tmpfile();
    Py_INCREF(Py_None);
    return Py_None;
    //error(FATAL, "gdb request failed: %s\n", cmd);
  }

  // Now read and print from fp
  rewind(pc->tmpfile);
  while (fgets(buf, BUFSIZE, pc->tmpfile)) {
    newpart = PyString_FromString(buf);
#if PY_MAJOR_VERSION >= 3    
    // On Python3: PyObject* PyUnicode_Concat(PyObject *left, PyObject *right)
    // and returns a new reference
    out = PyUnicode_Concat(out, newpart);
#else    
    // On Python2: void PyString_Concat(PyObject **string, PyObject *newpart)
    // The reference to the old value of string will be stolen
    PyString_Concat(&out, newpart);
#endif    
    Py_DECREF(newpart);
    //fputs(buf, stderr);
  }
  
  close_tmpfile();

  //Py_INCREF(Py_None);
  return out;
}

// Set an alarm clock and raise SIGINT to trigger calling of
// internal 'crash' handler
#define MAX_SIGINTS_ACCEPTED  (3)
static void
pykdump_except_handler(int sig) {
  //printf("ALARM\n");
  longjmp(alarm_env, 1);
}

static struct sigaction act;
static struct sigaction oldact;

static void set_alarm(int secs) {
  if (secs) {
    alarm(secs);
    BZERO(&act, sizeof(struct sigaction));
    act.sa_handler = pykdump_except_handler;
    act.sa_flags = SA_NOMASK;
    sigaction(SIGALRM, &act, &oldact);
    
  } else {
    alarm(0);
    //sigaction(SIGALRM, &oldact, NULL);
  }
}

// This command opens and writes to FIFO so we expect someone to read it
// It would be probably better to do all reading right here but at this
// moment we rely on Python part to do this
static int __default_timeout = 60;

static PyObject *
py_exec_crash_command(PyObject *self, PyObject *pyargs) {
  char *cmd;
  // char buf[BUFSIZE];
  FILE *oldfp = fp;
  int flength;			/* Length of a temporary file */
  int rlength;
  char *tmpbuf;
  PyObject *obj;

  int internal_error = 0;	/* crash/GDB error */
  
  int timeout = __default_timeout; 

  if (!PyArg_ParseTuple(pyargs, "s|i", &cmd, &timeout)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }

  if (debug > 1)
    printf("exec_crash_command <%s>, timeout=%ds\n", cmd, timeout);
  // Send command to crash and get its text output

  strcpy(pc->command_line, cmd);
  clean_line(pc->command_line);
  strcpy(pc->orig_line, pc->command_line);
  strip_linefeeds(pc->orig_line);
  
  argcnt = parse_line(pc->command_line, args);
  fflush(fp);
  
  fp = tmpfile();

  set_alarm(timeout);

  if (setjmp(alarm_env)) {
    // Recovery after timeout. We have interrupted internal processing
    // of crash/gdb, so we need to do crash-specific cleanup, e.g.
    // close temporary fds and free buffers
    PyObject *wmsg = PyDict_GetItemString(d, "WARNING"); /* Borrowed */
    // ------- minimal cleanup for crash itself -----------
    if (pc->tmpfile) {
	    close_tmpfile();
    }

    if (pc->tmpfile2) {
        close_tmpfile2();
    }
    restore_gdb_sanity();
    free_all_bufs();
    // -----------------------------------------------------
    
    fclose(fp);
    fp = oldfp;
    printf("%s <%s> failed to complete within the timeout period of %ds\n",
	   PyString_AsString(wmsg),  cmd, timeout);
    return PyString_FromString("");
  }
  
  /*
    crash uses longjmp(pc->main_loop_env) to recovers after some errors.
    This puts us into its main loop: read line/process command. As we
    don't want this, we'll replace pc->main_loop_env with our own location,
    and later will restore it.
   */
  
  // Copy the old location
  memcpy(copy_pc_env, pc->main_loop_env, sizeof(jmp_buf));
  if (!setjmp(pc->main_loop_env)) {
    exec_command();
  } else {
    // There was an internal GDB/crash error
    internal_error = 1;
  }

  // Make pc->main_loop_env point to its original location
  memcpy(pc->main_loop_env, copy_pc_env, sizeof(jmp_buf));

  // Now read from the temporary file
  fflush(fp);
  flength = ftell(fp);
  fseek(fp, 0,0);
  tmpbuf = malloc(flength);
  rlength =  fread(tmpbuf, 1, flength, fp);
  obj = PyString_FromStringAndSize(tmpbuf, flength);
  free(tmpbuf);
  
  fclose(fp);
  fp = oldfp;
  set_alarm(0);

  // If there was an error, we raise an exception and pass obj to it
  if (internal_error || rlength == 0) {
    PyErr_SetObject(crashError, obj);
    return NULL;
  }
  
  return obj;
}

// Call epython_execute_prog(argc, argv, 0)
static PyObject *
py_exec_epython_command(PyObject *self, PyObject *pyargs) {
  int argc = PyTuple_Size(pyargs);
  int i;
  
  char **argv = (char **) malloc(sizeof(char *) * argc);

  for (i=0; i < argc; i++)
    argv[i] = PyString_AsString(PyTuple_GetItem(pyargs, i));
  epython_execute_prog(argc, argv, 0);
  free(argv);

  Py_INCREF(Py_None);
  return Py_None;
}

#if 0
static PyObject *
oldpy_exec_crash_command(PyObject *self, PyObject *pyargs) {
  char *cmd;
  // char buf[BUFSIZE];
  FILE *oldfp = fp;


  if (!PyArg_ParseTuple(pyargs, "s", &cmd)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }


  // Send command to crash and get its text output
  strcpy(pc->command_line, cmd);
  clean_line(pc->command_line);
  
  argcnt = parse_line(pc->command_line, args);
  fflush(fp);
  
  Py_BEGIN_ALLOW_THREADS
  fp = fopen("PYT_fifo", "a");
  
  exec_command();
  fflush(fp);
  fclose(fp);
  Py_END_ALLOW_THREADS
    
  fp = oldfp;

  Py_INCREF(Py_None);
  return Py_None;
}
#endif


static PyObject *
py_sym2addr(PyObject *self, PyObject *args) {
  char *symbol;
  unsigned long long addr;
  struct syment *se;
     
  if (!PyArg_ParseTuple(args, "s", &symbol)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }

  se = symbol_search(symbol);

  if (se)
    addr = se->value;
  else
    addr = 0;
  
  // ASID
  //printf("addr=%lx\n", addr);
  //return Py_BuildValue("K", (unsigned long long) addr);
  return PyLong_FromUnsignedLong(addr);
}

extern  struct syment * symbol_search_next(char *, struct syment *) __attribute__ ((weak));


/* =========================WARNING=====================================
   We have to copy the following code from crash sources as symbol_search_next()
   is at this moment declared as static. Dave Anderson will make it visible 
   in 5.0.9. As soon as it becomes visible, it'll be used automatically
*/

#define MODULE_PSEUDO_SYMBOL(sp) \
    (STRNEQ((sp)->name, "_MODULE_START_") || STRNEQ((sp)->name, "_MODULE_END_"))

#define MODULE_START(sp) (STRNEQ((sp)->name, "_MODULE_START_"))
#define MODULE_END(sp)   (STRNEQ((sp)->name, "_MODULE_END_"))

/*
 *  Return the syment of the next symbol with the same name of the input symbol.
 */
static struct syment *
my_symbol_search_next(char *s, struct syment *spstart)
{
	int i;
        struct syment *sp, *sp_end;
	struct load_module *lm;
	int found_start;
	int pseudos;

	found_start = FALSE;

        for (sp = st->symtable; sp < st->symend; sp++) {
		if (sp == spstart) {
			found_start = TRUE;
			continue;
		} else if (!found_start)
			continue;

                if (strcmp(s, sp->name) == 0) {
                        return(sp);
		}
        }

	pseudos = (strstr(s, "_MODULE_START_") || strstr(s, "_MODULE_END_"));

        for (i = 0; i < st->mods_installed; i++) {
                lm = &st->load_modules[i];
		sp = lm->mod_symtable;
                sp_end = lm->mod_symend;

                for ( ; sp < sp_end; sp++) {
                	if (!pseudos && MODULE_PSEUDO_SYMBOL(sp))
                        	continue;

			if (sp == spstart) {
				found_start = TRUE;
				continue;
			} else if (!found_start)
				continue;

                	if (STREQ(s, sp->name))
                        	return(sp);
                }
        }

        return((struct syment *)NULL);
}


static PyObject *
py_sym2_alladdr(PyObject *self, PyObject *args) {
  char *symbol;
  unsigned long long addr;
  struct syment *se;
  PyObject *list;
  struct syment *(*ssn)(char *, struct syment *);

  if (symbol_search_next) {
    ssn = symbol_search_next;
    if (debug > 0)
      fprintf(fp, "Using CRASH's version of symbol_search_next\n");
  } else {
    ssn = my_symbol_search_next;
    if (debug > 0)
      fprintf(fp, "Using my own version of symbol_search_next\n");
  }

     
  if (!PyArg_ParseTuple(args, "s", &symbol)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }

  se = symbol_search(symbol);

  if (se)
    addr = se->value;
  else
    addr = 0;

  list = PyList_New(0);
  if (addr)
    if (PyList_Append(list,PyLong_FromUnsignedLong(addr)) == -1)
      return NULL;

  // Are there additional symbols?
  while ((se = ssn(symbol, se)))
    if (PyList_Append(list,PyLong_FromUnsignedLong(se->value)) == -1)
      return NULL;
  // ASID
  //printf("addr=%lx\n", addr);
  //return Py_BuildValue("K", (unsigned long long) addr);
  return list;
}

// A switch table - call the needed function based on integer object
// size

typedef PyObject * (*conversion_func)(const char *p);
static conversion_func functable_signed[16];
static conversion_func functable_usigned[16];


#if 0
// The following nu_xxxx routines are copied from Python's 'structmodule.c'
static PyObject *
nu_char(const char *p)
{
        return PyString_FromStringAndSize(p, 1);
}
#endif

static PyObject *
nu_byte(const char *p)
{
        return PyInt_FromLong((long) *(signed char *)p);
}

static PyObject *
nu_ubyte(const char *p)
{
        return PyInt_FromLong((long) *(unsigned char *)p);
}

static PyObject *
nu_short(const char *p)
{
        short x;
        memcpy((char *)&x, p, sizeof x);
        return PyInt_FromLong((long)x);
}

static PyObject *
nu_ushort(const char *p)
{
        unsigned short x;
        memcpy((char *)&x, p, sizeof x);
        return PyInt_FromLong((long)x);
}

static PyObject *
nu_int(const char *p)
{
        int x;
        memcpy((char *)&x, p, sizeof x);
        return PyInt_FromLong((long)x);
}

static PyObject *
nu_uint(const char *p)
{
        unsigned int x;
        memcpy((char *)&x, p, sizeof x);
        return PyLong_FromUnsignedLong((unsigned long)x);
}

static PyObject *
nu_long(const char *p)
{
        long x;
        memcpy((char *)&x, p, sizeof x);
        return PyInt_FromLong(x);
}

static PyObject *
nu_ulong(const char *p)
{
        unsigned long x;
        memcpy((char *)&x, p, sizeof x);
        return PyLong_FromUnsignedLong(x);
}

/* Native mode doesn't support q or Q unless the platform C supports
   long long (or, on Windows, __int64). */

#ifdef HAVE_LONG_LONG

static PyObject *
nu_longlong(const char *p)
{
        PY_LONG_LONG x;
        memcpy((char *)&x, p, sizeof x);
        return PyLong_FromLongLong(x);
}

static PyObject *
nu_ulonglong(const char *p)
{
        unsigned PY_LONG_LONG x;
        memcpy((char *)&x, p, sizeof x);
        return PyLong_FromUnsignedLongLong(x);
}

#endif

#if 0
static PyObject *
nu_float(const char *p)
{
        float x;
        memcpy((char *)&x, p, sizeof x);
        return PyFloat_FromDouble((double)x);
}

static PyObject *
nu_double(const char *p)
{
        double x;
        memcpy((char *)&x, p, sizeof x);
        return PyFloat_FromDouble(x);
}
#endif

static PyObject *
nu_void_p(void *p)
{
  //void *x;
  //memcpy((char *)&x, p, sizeof x);
  // The next line works incorrectly as it produces a signed value
  //return PyLong_FromVoidPtr(x);
  return functable_usigned[sizeof(void *)-1](p);
}

static PyObject *
nu_badsize(const char *p) {
  PyErr_SetString(crashError, "bad size");
  return NULL;
}




static PyObject *
py_mem2long(PyObject *self, PyObject *args, PyObject *kwds) {
  char *str;
  int size;
  // unsigned long addr;

  static char *kwlist[] = {"source", "signed", "array", NULL};
  int array = 0;
  int signedvar = 0;

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "s#|ii", kwlist,
				   &str, &size,
				   &signedvar, &array)) {
    //PyErr_SetString(crashError, "invalid parameter type");
    return NULL;
  }

  //printf("strsize=%d, signed=%d, array=%d\n",size, signedvar, array);

  if (array <= 1) {
    if (size < 0 || size > sizeof(functable_signed)/sizeof(conversion_func))
      return nu_badsize(str);
    if (signedvar)
      return functable_signed[size-1](str);
    else
      return functable_usigned[size-1](str);
  } else {
    /* We have an array */
    int sz1 = size/array;
    int i;
    PyObject *list, *val;
    if (size < 0 || sz1*array != size ||
	sz1 > sizeof(functable_signed)/sizeof(conversion_func))
      return nu_badsize(str);

    list = PyList_New(0);
    for (i=0; i < array; i++) {
      if (signedvar)
	val = functable_signed[sz1-1](str + sz1*i);
      else
	val = functable_usigned[sz1-1](str + sz1 * i);
      if (PyList_Append(list, val) == -1)
	return NULL;
    }
    return list;
  }
  return NULL;
}

static PyObject *
py_readPtr(PyObject *self, PyObject *args) {
  void *p;
  ulonglong addr;
  // int size;
  // void *buffer;
  char pb[256];

  // PyObject *out;

  PyObject *arg1 = PyTuple_GetItem(args, 0);
  int mtype = default_mtype;
  if (PyTuple_Size(args) > 1)
    mtype = PyInt_AsLong(PyTuple_GetItem(args, 1));

  addr = PyLong_AsUnsignedLongLong(arg1);
  /* When we see a NULL pointer we raise not a crash-specific
     exception but rather IndexError. This is useful as we often
     need to detect NULL pointers, e.g. the end of list marker
  */
  if (!addr) {
    sprintf(pb, "readPtr NULL pointer");
    PyErr_SetString(PyExc_IndexError, pb);
    return NULL;
  }
  if (readmem(addr, mtype, &p, sizeof(void *), "Python",
	      RETURN_ON_ERROR|QUIET) == FALSE) {
    sprintf(pb, "readmem error at addr 0x%llx", addr);
    PyErr_SetString(crashError, pb);
    return NULL;
    
  }
  return nu_void_p(&p);
}


static PyObject *
py_addr2sym(PyObject *self, PyObject *args) {
  // char *symbol;
  unsigned long addr;
  ulong offset;

  struct syment *se;
     
  if (!PyArg_ParseTuple(args, "k", &addr)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }

  se = value_search(addr, &offset);

  if (se && offset == 0)
    return Py_BuildValue("s", se->name);
  else
    return Py_BuildValue("s", NULL);
}

//int readmem(ulonglong addr, int memtype, void *buffer, long size,
//	char *type, ulong error_handle)

// With Python2, we return a 'str' object
// With Python3, we return a 'bytes' object

static PyObject *
py_readmem(PyObject *self, PyObject *args) {
  char pb[256];
  // char *symbol;
  ulonglong addr;
  long size;
  void *buffer;

  PyObject *out;

  PyObject *arg1 = PyTuple_GetItem(args, 0);
  PyObject *arg2 = PyTuple_GetItem(args, 1);
  int mtype = default_mtype;
  if (PyTuple_Size(args) > 2)
    mtype = PyInt_AsLong(PyTuple_GetItem(args, 2));

  /* This is buggy on 64-bit - sign is incorrect
  if (!PyArg_ParseTuple(args, "kl", &addr, &size)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }
  */
#if PY_MAJOR_VERSION < 3  
  if (PyInt_Check(arg1))
      addr = PyInt_AsLong(arg1);
  else
       addr = PyLong_AsUnsignedLongLong(arg1);
#else
  // Wtih Python3, integers are always long
  addr = PyLong_AsUnsignedLongLong(arg1);
#endif
  size = PyLong_AsLong(arg2);

  /* When we see a NULL pointer we raise not a crash-specific
     exception but rather IndexError. This is useful as we often
     need to detect NULL pointers, e.g. the end of list marker
  */

  if (!addr) {
    sprintf(pb, "readPtr NULL pointer");
    PyErr_SetString(PyExc_IndexError, pb);
    return NULL;
  }

  buffer = (void *) malloc(size);
  // printf("trying to read %ld bytes from %p %p\n", size, addr, buffer);
  if (readmem(addr, mtype, buffer, size, "Python",
	      RETURN_ON_ERROR|QUIET) == FALSE) {
    sprintf(pb, "readmem error at addr 0x%llx, reading %ld bytes", addr, size);
    PyErr_SetString(crashError, pb);
    return NULL;
    
  }
#if PY_MAJOR_VERSION < 3  
  out = PyString_FromStringAndSize(buffer, size);
#else
  out = PyBytes_FromStringAndSize(buffer, size);
#endif
  free(buffer);
  return out;
  
}

/* Read an integer (not an array of integers)
   To improve the performance, we assume that sizeof of any integer is not
   greater than 32 and use a predefined buffer for that

   Args: addr, size, signed (False/True)
*/
static PyObject *
py_readInt(PyObject *self, PyObject *args) {
  // char *symbol;
  ulonglong addr;
  long size;
  int signedvar = 0;		/* The default */
  int mtype = default_mtype;
  char buffer[32];

  // PyObject *out;

  PyObject *arg1 = PyTuple_GetItem(args, 0);
  PyObject *arg2 = PyTuple_GetItem(args, 1);

  if (PyTuple_Size(args) > 2)
    signedvar = PyInt_AsLong(PyTuple_GetItem(args, 2));

  addr = PyLong_AsUnsignedLongLong(arg1);
  size = PyLong_AsLong(arg2);

  if (size > 32) {
    char pb[256];
    sprintf(pb, "readInt cannot read reading %ld bytes", size);
    PyErr_SetString(crashError, pb);
    return NULL;
  }

  if (readmem(addr, mtype, buffer, size, "Python",
	      RETURN_ON_ERROR|QUIET) == FALSE) {
    char pb[256];
    sprintf(pb, "readmem/py_readInt error at addr 0x%llx, reading %ld bytes",
	    addr, size);
    PyErr_SetString(crashError, pb);
    return NULL;
    
  }
  if (size < 0 || size > sizeof(functable_signed)/sizeof(conversion_func))
    return nu_badsize(buffer);
  if (signedvar)
    return functable_signed[size-1](buffer);
  else
    return functable_usigned[size-1](buffer);
}


/*
  Set default readmem operations to use UVADDR for task
  readmem_task(taskaddr)  - set to UVADDR and set the current context
  readmem_task(0)           - reset to KVADDR
*/
static PyObject *
py_readmem_task(PyObject *self, PyObject *args) {
  ulong tskaddr;
  struct task_context *task;
  static struct task_context *prev_task = NULL;

  PyObject *arg0 = PyTuple_GetItem(args, 0);

  if (PyInt_Check(arg0))
      tskaddr = PyInt_AsLong(arg0);
  else
      tskaddr = PyLong_AsUnsignedLongLong(arg0);

  if (tskaddr) {
    task = task_to_context(tskaddr);
    if (!task) {
      PyErr_SetString(crashError, "bad taskaddr"); \
      return NULL;
    }
    prev_task = tt->current;
    tt->current = task;
    default_mtype = UVADDR;
  } else {
    default_mtype = KVADDR;
    if (prev_task)
      tt->current = prev_task;
  }
  Py_INCREF(Py_None);
  return Py_None;
}


/* 
   Copied from crash/kernel.c - it is declared as static there,
   so we have to duplicate
 */
static int
get_NR_syscalls(void)
{
        ulong sys_call_table;
        struct syment *sp;
        int cnt;

        sys_call_table = symbol_value("sys_call_table");
        if (!(sp = next_symbol("sys_call_table", NULL)))
                return 256;

        while (sp->value == sys_call_table) {
                if (!(sp = next_symbol(sp->name, NULL)))
                        return 256;
        }

        if (machine_type("S390X"))
                cnt = (sp->value - sys_call_table)/sizeof(int);
        else
                cnt = (sp->value - sys_call_table)/sizeof(void *);

        return cnt;
}

static PyObject *
py_get_NR_syscalls(PyObject *self, PyObject *args) {
    return PyInt_FromLong(get_NR_syscalls());
}

/*
  physaddr = uvtop(tskaddr, vaddr)
*/

static PyObject *
py_uvtop(PyObject *self, PyObject *args) {
  physaddr_t physaddr;
  ulong tskaddr, vaddr;
  int verbose = 0;

  PyObject *arg0 = PyTuple_GetItem(args, 0);
  PyObject *arg1 = PyTuple_GetItem(args, 1);

  tskaddr = PyLong_AsUnsignedLong(arg0);
  vaddr = PyLong_AsUnsignedLong(arg1);

  // uvtop(struct task_context *tc,ulong vaddr,physaddr_t *paddr,int verbose)

  if (!uvtop(task_to_context(tskaddr), vaddr, &physaddr, verbose)) {
    // We cannot convert
    char pb[256];
    sprintf(pb, "uvtop error at vaddr 0x%llx", (long long unsigned) vaddr);
    PyErr_SetString(crashError, pb);
    return NULL;
  }

  return PyLong_FromUnsignedLongLong((ulonglong)physaddr);
}
  

static PyObject *
py_pageoffset(PyObject *self, PyObject *args) {
  ulong vaddr;

  if (!PyArg_ParseTuple(args, "k", &vaddr)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }

  return PyLong_FromUnsignedLong(PAGEOFFSET(vaddr));
}
				 
  
  


static PyObject *
py_getFullBuckets(PyObject *self, PyObject *args) {
  ulonglong start;
  int bsize, items, chain_off;

  char *buffer;

  PyObject* list;
  void *bucket;
  int i;

  if (!PyArg_ParseTuple(args, "Kiii",
			&start,
			&bsize, &items, &chain_off)) {
     PyErr_SetString(crashError, "bad arguments");
    return NULL;
  }

  buffer = (void *) malloc(bsize*items);
  if (!buffer) {
    PyErr_SetString(crashError, "cannot malloc");
    return NULL;
  }
  //printf("start=0x%llx, bsize=%d items=%d  chain_off=%d\n",
  //	 start, bsize, items, chain_off);
  //readmem(start, KVADDR, buffer, bsize*items, "Python", FAULT_ON_ERROR);
  if (readmem(start, KVADDR, buffer, bsize*items, "Python",
	      RETURN_ON_ERROR|QUIET) == FALSE) {
    char pb[256];
    sprintf(pb, "readmem error at addr 0x%llx", start);	\
    PyErr_SetString(crashError, pb);
    return NULL;
    
  }
  list = PyList_New(0);
  for (i=0; i < items; i++) {
        memcpy((char *)&bucket, buffer+i*bsize+chain_off, sizeof bucket);
	if (bucket) {
	  /* Python 2.4.3 has PyLong_FromVoidPtr but it converts to Int with
	     sign - a bug, need report this to Python team */
	  PyList_Append(list, PyLong_FromUnsignedLong((unsigned long)bucket));
	}
  }
  free(buffer);
  return list;
}

/* Find a total number of elements in a list specified with addr, offset
   Usage: count = getListSize(addr, offset, maxel = 1000)
   We do not include the list_head
*/

static PyObject *
py_getlistsize(PyObject *self, PyObject *args) {
  char *addr;
  long offset;
  long maxel;
  
  char pb[256];
  
  int count = 0;
  char *ptr, *next;
  
  PyObject *arg0 = PyTuple_GetItem(args, 0);
  PyObject *arg1 = PyTuple_GetItem(args, 1);
  PyObject *arg2 = PyTuple_GetItem(args, 2);

  ptr = addr = (char *) PyLong_AsUnsignedLong(arg0);
  offset = PyLong_AsLong(arg1);
  maxel = PyLong_AsLong(arg2);

  // readmem(ulonglong addr, int memtype, void *buffer, long size,
  //         char *type, ulong error_handle)
  while (ptr && count < maxel) {
    /* next = readPtr(ptr+offset) */
    if (readmem((ulonglong)(ulong)(ptr + offset), KVADDR, &next,
		sizeof(void *), "Python", RETURN_ON_ERROR|QUIET) == FALSE) {
          sprintf(pb, "readmem error at addr %p", addr);	\
	  PyErr_SetString(crashError, pb);
	  return NULL;
    }

    //printf("addr=%p next=%p\n", addr, next); 
    if (next == addr)
      break;
    ptr = next;
    count++;
  }
  return PyInt_FromLong(count);
}

static PyObject *
py_FD_ISSET(PyObject *self, PyObject *args) {
  char *str;
  int fd, lstr;

  if (!PyArg_ParseTuple(args, "is#", &fd, &str, &lstr)) {
    PyErr_SetString(crashError, "invalid parameter type");
    return NULL;
  }

  return Py_BuildValue("i", FD_ISSET(fd, (fd_set *)str));
}


static PyObject *
py_sLong(PyObject *self, PyObject *args) {
  ulong val;

  PyObject *arg0 = PyTuple_GetItem(args, 0);
  val = PyLong_AsUnsignedLong(arg0);
  return nu_long((const char *) &val);
}

static PyObject *
py_le32_to_cpu(PyObject *self, PyObject *args) {
  ulong val;

  if (!PyArg_ParseTuple(args, "k", &val)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }
  
  return PyLong_FromUnsignedLong(__le32_to_cpu(val));
}

static PyObject *
py_le16_to_cpu(PyObject *self, PyObject *args) {
  ulong val;
  
  if (!PyArg_ParseTuple(args, "k", &val)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }

  //PyObject *arg0 = PyTuple_GetItem(args, 0);
  //val = PyLong_AsUnsignedLong(arg0);
  return PyLong_FromUnsignedLong(__le16_to_cpu(val));
}

#if 0
static PyObject *
py_cpu_to_le32(PyObject *self, PyObject *args) {
  ulong val;
  
  if (!PyArg_ParseTuple(args, "k", &val)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }


  return PyLong_FromUnsignedLong(__cpu_to_le32(val));
}
#endif


/*
  Register epython program as crash extension. Both arguments are strings
  register_epython_prog(cmd, help)
*/

static void
epython_subcommand(void) {
  epython_execute_prog(argcnt, args, 0);
}


static PyObject *
py_register_epython_prog(PyObject *self, PyObject *args) {
  //char *cmd, *short_description, *synopsis, *help;
  char *help_data[4];
  char *cmd;
  // long val;
  int i;
  int totlen;
  // struct command_table_entry *cp;

  int nentries;

  struct command_table_entry *ct = epython_curext->command_table;
  struct command_table_entry *ce;

     
  if (!PyArg_ParseTuple(args, "ssss", &help_data[0],
			&help_data[1],  &help_data[2],
			&help_data[3])) {
    PyErr_SetString(crashError, "invalid parameter(s) type"); \
    return NULL;
  }

  cmd = help_data[0];
  if (debug > 1)
    printf("Registering %s\n", cmd);

  /* Check for name clash */
  if (get_command_table_entry(cmd)) {
    error(INFO, "%s: \"%s\" is a duplicate of a currently-existing command\n",
	  pc->curext->filename, cmd);
    Py_RETURN_FALSE;
  }

  if (is_alias(cmd)) {
    error(INFO,  "alias \"%s\" deleted: name clash with extension command\n",
	  cmd);
    deallocate_alias(cmd);
  }


  /* Epython's command_table is already registered. Instead of using
     a static table of predefined big size, we use realloc as needed
  */

  for(ce=ct, nentries = 0; ce->name; ce++, nentries++);

  if (debug > 1)
    printf("nentries=%d\n", nentries);
  
  ct = realloc(ct, sizeof(struct command_table_entry)*(nentries+2));
  if (!ct) {
    printf("Cannot realloc while registering epython/%s\n", cmd);
  } else {
    // Add a new entry
    ce = ct + nentries;
    // Alloc memory for name
    ce->name = (char *) malloc(strlen(cmd) + 1);
    if (ce->name)
      strcpy(ce->name, cmd);
    else {
      printf("malloc() failed in py_register_epython_prog\n");
      free(ct);
      return PyErr_NoMemory();
    }
    ce->func = epython_subcommand;

    totlen = 5 * sizeof(char *);
    for (i=0; i < 4; i++)
      totlen += (strlen(help_data[i]) + 1);
    ce->help_data = (char **) malloc(totlen);
    if (!ce->help_data) {
      printf("malloc() failed for help_data in py_register_epython_prog\n");
    } else {
      char **aptr = ce->help_data;
      char *sptr = (char *) (aptr + 5);
      for (i=0; i < 4; i++) {
	// int l = strlen(help_data[i]);
	*aptr++ = sptr;
	strcpy(sptr, help_data[i]);
	sptr += strlen(help_data[i]) + 1;
      }
      *aptr = NULL;
    }
    ce->flags = 0;

    // Put the new EOT marker
    (ce+1)->name = NULL;

    // Update the table in crash
    epython_curext->command_table = ct;
  }
  
  // Print cmd table for debugging
  if (debug > 1) {
    printf("--- Current command table ---\n");
    for (ce = epython_curext->command_table; ce->name; ce++) {
      printf("name=%s\n", ce->name);
    }
  }

  Py_RETURN_TRUE;
}

// Return the list of epython registered commands


/* Set default timeout value for exec_crash_command */
static PyObject *
py_get_epython_cmds(PyObject *self, PyObject *args) {
  struct command_table_entry *ce;
  PyObject *list, *val;
  list = PyList_New(0);
  for (ce = epython_curext->command_table; ce->name; ce++) {
    val = PyString_FromString(ce->name);
    if (PyList_Append(list, val) == -1)
      return NULL;
  }
  return list;
}

/* Set default timeout value for exec_crash_command */
static PyObject *
py_set_default_timeout(PyObject *self, PyObject *args) {
  int old_value = __default_timeout;
  if (!PyArg_ParseTuple(args, "i", &__default_timeout)) {
    PyErr_SetString(crashError, "invalid parameter type");
    __default_timeout = old_value;
    return NULL;
  }
  return PyInt_FromLong((long) old_value);
}

static PyObject *
py_get_pathname(PyObject *self, PyObject *args) {

  ulong dentry, vfsmnt;
  char pathname[BUFSIZE];
  if (!PyArg_ParseTuple(args, "kk", &dentry, &vfsmnt)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }

  get_pathname(dentry, pathname, sizeof(pathname), 1, vfsmnt);
  return PyString_FromString(pathname);
}

PyObject * py_gdb_typeinfo(PyObject *self, PyObject *args);
PyObject * py_gdb_whatis(PyObject *self, PyObject *args);
void py_gdb_register_enums(PyObject *m);


static PyMethodDef crashMethods[] = {
  {"symbol_exists",  py_crash_symbol_exists, METH_VARARGS},
  {"struct_size",  py_crash_struct_size, METH_VARARGS},
  {"union_size",  py_crash_union_size, METH_VARARGS},
  {"member_offset",  py_crash_member_offset, METH_VARARGS},
  {"member_size",  py_crash_member_size, METH_VARARGS},
  {"get_symbol_type",  py_crash_get_symbol_type, METH_VARARGS},
  {"get_GDB_output",  py_get_GDB_output, METH_VARARGS},
  {"exec_crash_command",  py_exec_crash_command, METH_VARARGS},
  {"exec_epython_command",  py_exec_epython_command, METH_VARARGS},
  {"get_epython_cmds",  py_get_epython_cmds, METH_VARARGS},
  {"sym2addr",  py_sym2addr, METH_VARARGS},
  {"sym2alladdr",  py_sym2_alladdr, METH_VARARGS},
  {"addr2sym",  py_addr2sym, METH_VARARGS},
  {"mem2long",  (PyCFunction)py_mem2long, METH_VARARGS | METH_KEYWORDS},
  {"uvtop",  py_uvtop, METH_VARARGS},
  {"PAGEOFFSET",  py_pageoffset, METH_VARARGS},
  {"readmem", py_readmem, METH_VARARGS},
  {"readPtr", py_readPtr, METH_VARARGS},
  {"readInt", py_readInt, METH_VARARGS},
  {"sLong", py_sLong, METH_VARARGS},
  {"le32_to_cpu", py_le32_to_cpu, METH_VARARGS},
  {"le16_to_cpu", py_le16_to_cpu, METH_VARARGS},
  {"cpu_to_le32", py_le32_to_cpu, METH_VARARGS},
  {"getListSize", py_getlistsize, METH_VARARGS},
  {"getFullBuckets", py_getFullBuckets, METH_VARARGS},
  {"FD_ISSET", py_FD_ISSET, METH_VARARGS},
  {"gdb_whatis", py_gdb_whatis, METH_VARARGS},
  {"gdb_typeinfo", py_gdb_typeinfo, METH_VARARGS},
  {"set_readmem_task", py_readmem_task, METH_VARARGS},
  {"get_NR_syscalls", py_get_NR_syscalls, METH_VARARGS},
  {"register_epython_prog", py_register_epython_prog, METH_VARARGS},
  {"set_default_timeout", py_set_default_timeout, METH_VARARGS},
  {"get_pathname", py_get_pathname, METH_VARARGS},
  {NULL,      NULL}        /* Sentinel */
};

#if PY_MAJOR_VERSION >= 3
    static struct PyModuleDef crashmodule = {
        PyModuleDef_HEAD_INIT,
        "crash",		/* m_name */
        "Low-level Python API to crash internals",  /* m_doc */
        -1,			/* m_size */
        crashMethods,		/* m_methods */
        NULL,			/* m_reload */
        NULL,			/* m_traverse */
        NULL,			/* m_clear */
        NULL,			/* m_free */
    };
#endif

extern const char * crashmod_version;

static PyObject *
initcrash23(void) {
  
  int i;
#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&crashmodule);
#else  
  m = Py_InitModule("crash", crashMethods);
#endif

  if (m == NULL)
        return NULL;
  
  d = PyModule_GetDict(m);
  crashError = PyErr_NewException("crash.error", NULL, NULL);
  Py_INCREF(crashError);
  PyModule_AddObject(m, "error", crashError);

  PyModule_AddObject(m, "version", PyString_FromString(crashmod_version));
  
  PyModule_AddObject(m, "KVADDR", PyInt_FromLong(KVADDR));
  PyModule_AddObject(m, "UVADDR", PyInt_FromLong(UVADDR));
  PyModule_AddObject(m, "PHYSADDR", PyInt_FromLong(PHYSADDR));
  PyModule_AddObject(m, "XENMACHADDR", PyInt_FromLong(XENMACHADDR));
  //PyModule_AddObject(m, "FILEADDR", PyInt_FromLong(FILEADDR));
  PyModule_AddObject(m, "AMBIGUOUS", PyInt_FromLong(AMBIGUOUS));

  PyModule_AddObject(m, "PAGESIZE", PyInt_FromLong(PAGESIZE()));
  PyModule_AddObject(m, "HZ", PyInt_FromLong(machdep->hz));

  PyModule_AddObject(m, "WARNING", PyString_FromString("++WARNING+++"));
  
  PyModule_AddObject(m, "Crash_run", PyString_FromString(build_version));
  PyModule_AddObject(m,
		     "Crash_build",PyString_FromString(build_crash_version));

  // Register GDB-internal enums
  py_gdb_register_enums(m);

  // Now create some aliases

  // Initialize size/type tables
  for (i=0; i < sizeof(functable_signed)/sizeof(conversion_func); i++) {
    functable_signed[i] = nu_badsize;
    functable_usigned[i] = nu_badsize;
  }
  
  functable_signed[sizeof(char)-1] = nu_byte;
  functable_signed[sizeof(short)-1] = nu_short;
  functable_signed[sizeof(int)-1] = nu_int;
  functable_signed[sizeof(long)-1] = nu_long;
  functable_signed[sizeof(long long)-1] = nu_longlong;

  functable_usigned[sizeof(char)-1] = nu_ubyte;
  functable_usigned[sizeof(short)-1] = nu_ushort;
  functable_usigned[sizeof(int)-1] = nu_uint;
  functable_usigned[sizeof(long)-1] = nu_ulong;
  functable_usigned[sizeof(long long)-1] = nu_ulonglong;

  return m;
}

#if PY_MAJOR_VERSION < 3
    PyMODINIT_FUNC initcrash(void)
    {
        initcrash23();
    }
#else
    PyMODINIT_FUNC PyInit_crash(void)
    {
        return initcrash23();
    }
#endif
