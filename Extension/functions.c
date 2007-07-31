/* Python extension to interact with CRASH
   
  Time-stamp: <07/07/12 17:08:45 alexs>

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
#include <stdlib.h>

#include "defs.h"    /* From the crash source top-level directory */

// for FD_ISSET
#include <sys/select.h>


/* crash exception */
static PyObject *crashError;


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
  printf("val=%d, length=%d, name=%s, typename=%s, tagname=%s\n",
	 val, req.length, req.name, req.typename, req.tagname);
  
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
    PyString_ConcatAndDel(&out, newpart);
    //fputs(buf, stderr);
  }
  
  close_tmpfile();

  //Py_INCREF(Py_None);
  return out;
}

// This command opens and writes to FIFO so we expect someone to read it
// It would be probably better to do all reading right here but at this
// moment we rely on Python part to do this
static PyObject *
py_exec_crash_command(PyObject *self, PyObject *pyargs) {
  char *cmd;
  char buf[BUFSIZE];
  FILE *oldfp = fp;
  int flength;			/* Length of a temporary file */
  char *tmpbuf;
  PyObject *obj;

  if (!PyArg_ParseTuple(pyargs, "s", &cmd)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }


  // Send command to crash and get its text output

  strcpy(pc->command_line, cmd);
  clean_line(pc->command_line);
  strcpy(pc->orig_line, pc->command_line);
  strip_linefeeds(pc->orig_line);
  
  argcnt = parse_line(pc->command_line, args);
  fflush(fp);
  
  fp = tmpfile();

  /* I use setjmp here as this is how crash recovers after some errors */
  if (!setjmp(pc->main_loop_env))
      exec_command();
  fflush(fp);

  // Now read from it
  flength = ftell(fp);
  fseek(fp, 0,0);
  tmpbuf = malloc(flength);
  fread(tmpbuf, flength, 1, fp);
  obj = PyString_FromStringAndSize(tmpbuf, flength);
  free(tmpbuf);
  fclose(fp);
  fp = oldfp;
  return obj;
}

static PyObject *
oldpy_exec_crash_command(PyObject *self, PyObject *pyargs) {
  char *cmd;
  char buf[BUFSIZE];
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

// A switch table - call the needed function based on integer object
// size

typedef PyObject * (*conversion_func)(const char *p);
static conversion_func functable_signed[16];
static conversion_func functable_usigned[16];


// The following nu_xxxx routines are copied from Python's 'structmodule.c'
static PyObject *
nu_char(const char *p)
{
        return PyString_FromStringAndSize(p, 1);
}

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

static PyObject *
nu_void_p(void *p)
{
        void *x;
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
  unsigned long addr;

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
  int size;
  void *buffer;
  char pb[256];

  PyObject *out;

  PyObject *arg1 = PyTuple_GetItem(args, 0);
  int mtype = KVADDR;
  if (PyTuple_Size(args) > 1)
    mtype = PyInt_AsLong(PyTuple_GetItem(args, 1));

  addr = PyLong_AsUnsignedLongLong(arg1);
  
  if (readmem(addr, mtype, &p, sizeof(void *), "Python",
	      RETURN_ON_ERROR) == FALSE) {
    sprintf(pb, "readmem error at addr 0x%llx", addr);	\
    PyErr_SetString(crashError, pb);
    return NULL;
    
  }
  return nu_void_p(&p);
}


static PyObject *
py_addr2sym(PyObject *self, PyObject *args) {
  char *symbol;
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

static PyObject *
py_readmem(PyObject *self, PyObject *args) {
  char *symbol;
  ulonglong addr;
  int size;
  void *buffer;

  PyObject *out;

  PyObject *arg1 = PyTuple_GetItem(args, 0);
  PyObject *arg2 = PyTuple_GetItem(args, 1);
  int mtype = KVADDR;
  if (PyTuple_Size(args) > 2)
    mtype = PyInt_AsLong(PyTuple_GetItem(args, 2));

  /* This is buggy on 64-bit - sign is incorrect
  if (!PyArg_ParseTuple(args, "kl", &addr, &size)) {
    PyErr_SetString(crashError, "invalid parameter type"); \
    return NULL;
  }
  */
  addr = PyLong_AsUnsignedLongLong(arg1);
  size = PyLong_AsLong(arg2);

  buffer = (void *) malloc(size);
  //printf("trying to read %ld bytes from %p %p\n", size, addr, buffer);
  if (readmem(addr, mtype, buffer, size, "Python",
	      RETURN_ON_ERROR) == FALSE) {
    char pb[256];
    sprintf(pb, "readmem error at addr 0x%llx", addr);
    PyErr_SetString(crashError, pb);
    return NULL;
    
  }
  out = PyString_FromStringAndSize(buffer, size);
  free(buffer);
  return out;
  
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
    sprintf(pb, "uvtop error at vaddr 0x%llx", vaddr);
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
	      RETURN_ON_ERROR) == FALSE) {
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
		sizeof(void *), "Python", RETURN_ON_ERROR) == FALSE) {
          sprintf(pb, "readmem error at addr 0x%llx", addr);	\
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
  void *p;
  ulong val;

  PyObject *arg0 = PyTuple_GetItem(args, 0);
  val = PyLong_AsUnsignedLong(arg0);
  return nu_long((const char *) &val);
}

  
#if 0
#include "gdb-6.1/gdb/objfiles.h"

static CORE_ADDR
ia64_convert_from_func_ptr_addr (CORE_ADDR addr)
{
  struct obj_section *s;

  s = find_pc_section (addr);

  /* check if ADDR points to a function descriptor.  */
  if (s && strcmp (s->the_bfd_section->name, ".opd") == 0)
    return read_memory_unsigned_integer (addr, 8);

  return addr;
}
#endif

static PyMethodDef crashMethods[] = {
  {"symbol_exists",  py_crash_symbol_exists, METH_VARARGS},
  {"struct_size",  py_crash_struct_size, METH_VARARGS},
  {"union_size",  py_crash_union_size, METH_VARARGS},
  {"member_offset",  py_crash_member_offset, METH_VARARGS},
  {"member_size",  py_crash_member_size, METH_VARARGS},
  {"get_symbol_type",  py_crash_get_symbol_type, METH_VARARGS},
  {"get_GDB_output",  py_get_GDB_output, METH_VARARGS},
  {"exec_crash_command",  py_exec_crash_command, METH_VARARGS},
  {"sym2addr",  py_sym2addr, METH_VARARGS},
  {"addr2sym",  py_addr2sym, METH_VARARGS},
  {"mem2long",  (PyCFunction)py_mem2long, METH_VARARGS | METH_KEYWORDS},
  {"uvtop",  py_uvtop, METH_VARARGS},
  {"PAGEOFFSET",  py_pageoffset, METH_VARARGS},
  {"readmem", py_readmem, METH_VARARGS},
  {"readPtr", py_readPtr, METH_VARARGS},
  {"sLong", py_sLong, METH_VARARGS},
  {"getListSize", py_getlistsize, METH_VARARGS},
  {"getFullBuckets", py_getFullBuckets, METH_VARARGS},
  {"FD_ISSET", py_FD_ISSET, METH_VARARGS},
  {NULL,      NULL}        /* Sentinel */
};

void
initcrash(const char *crash_version) {
  PyObject *m, *d;
  int i;
  
  m = Py_InitModule("crash", crashMethods);
  //d = PyModule_GetDict(m);
  crashError = PyErr_NewException("crash.error", NULL, NULL);
  Py_INCREF(crashError);
  PyModule_AddObject(m, "error", crashError);

  PyModule_AddObject(m, "version", PyString_FromString(crash_version));
  
  PyModule_AddObject(m, "KVADDR", PyInt_FromLong(KVADDR));
  PyModule_AddObject(m, "UVADDR", PyInt_FromLong(UVADDR));
  PyModule_AddObject(m, "PHYSADDR", PyInt_FromLong(PHYSADDR));
  PyModule_AddObject(m, "XENMACHADDR", PyInt_FromLong(XENMACHADDR));
  PyModule_AddObject(m, "FILEADDR", PyInt_FromLong(FILEADDR));
  PyModule_AddObject(m, "AMBIGUOUS", PyInt_FromLong(AMBIGUOUS));

  PyModule_AddObject(m, "PAGESIZE", PyInt_FromLong(PAGESIZE()));

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
}
