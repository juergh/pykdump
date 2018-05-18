/* Python extension to interact with CRASH - GDB-specific subroutines


// --------------------------------------------------------------------
// (C) Copyright 2006-2018 Hewlett-Packard Enterprise Development LP
//
// Author: Alex Sidorenko <asid@hpe.com>
//
// --------------------------------------------------------------------

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

#include "defs.h"
#include "pykdump.h"

#include "gdb_obstack.h"
#include "bfd.h"		/* Binary File Description */
#include "symtab.h"
#include "gdbtypes.h"
#include "expression.h"
#include "value.h"
#include "gdbcore.h"
#include "target.h"
#include "language.h"
#include "demangle.h"
#include "c-lang.h"
#include "typeprint.h"
#include "cp-abi.h"

#include "gdb_string.h"
#include <errno.h>
#include <setjmp.h>

#if defined(ATTR_NORETURN)
typedef NORETURN void (*ERROR_HOOK_TYPE) (void) ATTR_NORETURN;
#else
typedef void (*ERROR_HOOK_TYPE)(void);
#endif

/* GDB-7 specific stuff */
#if defined(GDB7)
ERROR_HOOK_TYPE error_hook;
#define VALUE_TYPE value_type
#endif


extern int debug;

extern PyObject *crashError;
//static void ptype_command (char *typename, int from_tty);
//static void whatis_exp (char *exp, int show);

static sigjmp_buf eenv;

//static ERROR_HOOK_TYPE old_error_hook;

static FILE *nullfp = NULL;

static void my_cleanups(void) {
  error_hook = NULL; \
  //printf("mycleanups\n");

}

// crash 6.X uses GDB version where we do do_cleanups(NULL);
// crash 7.X uses a newer GDB which needs do_cleanups(all_cleanups())

#if defined(GDB76)
#define PY_DO_CLEANUPS (do_cleanups(all_cleanups()))
#else
#define PY_DO_CLEANUPS (do_cleanups((struct cleanup *)0))
#endif

static void
my_error_hook(void)  {
  //printf("Error hook\n");

  PY_DO_CLEANUPS;
  my_cleanups();
  longjmp(eenv, 1);
}

int
myDict_SetCharChar(PyObject *v, const char *key, const char *item) {
	PyObject *iv;
	int err;
	iv = PyString_FromString(item);
	if (iv == NULL)
		return -1;
	err = PyDict_SetItemString(v, key, iv);
	Py_DECREF(iv);
	return err;
}


/* If GDB error was caught, raise Python exception. Cleanup is
   already done in my_error_hook
*/

/* Prepare to run a function calling directly GDB internals. We substitute
 */

extern void replace_ui_file_FILE(struct ui_file *, FILE *);

#define GDB2PY_ENTER \
  do { \
    if (!nullfp) \
      nullfp = fopen("/dev/null", "w+");		\
    error_hook = (ERROR_HOOK_TYPE) my_error_hook;	\
    replace_ui_file_FILE(gdb_stdout, nullfp); \
    replace_ui_file_FILE(gdb_stderr, nullfp); \
    PY_DO_CLEANUPS; \
    \
    if (setjmp(eenv)) { \
      PyErr_SetString(crashError, "PyKdump/GDB error");\
      return NULL; \
    } \
  } while (0)


#define GDB2PY_EXIT \
  do { \
    my_cleanups(); \
  } while (0)


# define X_GDB2PY_ENTER while(0)
# define X_GDB2PY_EXIT while(0)

static struct type *
ptype_eval (struct expression *exp)
{
  if (exp->elts[0].opcode == OP_TYPE)
    {
      return (exp->elts[1].type);
    }
  else
    {
      return (NULL);
    }
}

static void do_SU(struct type *type, PyObject *dict);
static void do_func(struct type *type, PyObject *dict);
static void do_enum(struct type *type, PyObject *pitem);

static void
do_ftype(struct type *ftype, PyObject *item) {
  const char *tagname = TYPE_TAG_NAME(ftype);
  //struct type *range_type;
  struct type *tmptype;

  PyObject *v;

  char buf[256];

  int i;

  int stars = 0;
  int dims[4] = {0,0,0,0};
  int ndim = 0;

  int codetype = TYPE_CODE(ftype);
  const char *typename = TYPE_NAME(ftype);
  PyObject *fname;
  PyObject *ptr;

  if(TYPE_STUB(ftype) && tagname) {
#if defined(GDB7)
    struct symbol *sym = lookup_symbol(tagname,
				       0, STRUCT_DOMAIN,
				       0);
#else
    struct symbol *sym = lookup_symbol(tagname,
				       0, STRUCT_DOMAIN,
				       0, (struct symtab **) NULL);
#endif
    if(sym) {
      ftype=sym->type;
    }
  }

  switch (codetype) {
  case TYPE_CODE_STRUCT:
  case TYPE_CODE_UNION:
    v = PyString_FromString("fname");
    fname = PyDict_GetItem(item, v);
    Py_DECREF(v);

    v = PyString_FromString("stars");
    ptr = PyDict_GetItem(item, v);
    Py_DECREF(v);
    /* Expand only if we don't have tagname or fname */
    if (tagname != NULL) {
      if (codetype == TYPE_CODE_STRUCT)
	sprintf(buf, "struct %s", tagname);
      else
	sprintf(buf, "union %s", tagname);
      if (fname == NULL && !ptr)
	do_SU(ftype, item);
    } else {
      if  (codetype == TYPE_CODE_STRUCT)
	sprintf(buf, "struct");
      else
	sprintf(buf, "union");
      if (!ptr)
	do_SU(ftype, item);
    }
    myDict_SetCharChar(item, "basetype", buf);
    break;
  case TYPE_CODE_ENUM:
    if (tagname != NULL) {
      sprintf(buf, "enum %s", tagname);
      do_enum(ftype, item);
    } else {
      /* Untagged enum */
      sprintf(buf, "enum");
      do_enum(ftype, item);
    }
    myDict_SetCharChar(item, "basetype", buf);
    break;
  case TYPE_CODE_PTR:
    tmptype = ftype;
    do {
      stars++;
    } while (TYPE_CODE(tmptype = TYPE_TARGET_TYPE(tmptype)) == TYPE_CODE_PTR);

    if (TYPE_CODE(tmptype) == TYPE_CODE_TYPEDEF) {
      const char *ttypename = TYPE_NAME(tmptype);
      if (ttypename)
	myDict_SetCharChar(item, "typedef", ttypename);
      CHECK_TYPEDEF(tmptype);
    }

    v =  PyInt_FromLong(stars);
    PyDict_SetItemString(item, "stars", v);
    Py_DECREF(v);

    v = PyInt_FromLong(TYPE_CODE(tmptype));
    PyDict_SetItemString(item, "ptrbasetype", v);
    Py_DECREF(v);

    do_ftype(tmptype, item);
    break;
  case TYPE_CODE_FUNC:
    myDict_SetCharChar(item, "basetype", "(func)");
    do_func(ftype, item);
    break;
  case TYPE_CODE_TYPEDEF:
    /* Add extra tag - typedef name. This is useful
       in struct/union case as we can cache info based on it */
    if (typename)
      myDict_SetCharChar(item, "typedef", typename);
    CHECK_TYPEDEF(ftype);
    do_ftype(ftype, item);
    break;
  case TYPE_CODE_INT:
    v= PyInt_FromLong(TYPE_UNSIGNED(ftype));
    PyDict_SetItemString(item, "uint", v);
    Py_DECREF(v);
    myDict_SetCharChar(item, "basetype", TYPE_NAME(ftype));
    break;
  case TYPE_CODE_ARRAY:
    /* Multidimensional C-arrays are visible as arrays of arrays.
       We need to recurse or iterate to obtain all dimensions
    */
    //printf("TYPE_CODE_ARRAY\n");
    do {
      LONGEST low_bound, high_bound;
      int dim;
      if (!get_array_bounds(ftype, &low_bound, &high_bound))
	dim = 0;
      else
	dim = high_bound + 1;

      ftype= TYPE_TARGET_TYPE(ftype);
     /* The following worked with older GDB, but not with 7.3.1
      range_type = TYPE_FIELD_TYPE (ftype, 0);
       dims[ndim++] = TYPE_FIELD_BITPOS(range_type, 1)+1;
      */
      //printf(" ndim=%d l=%ld\n", ndim, high_bound);
      dims[ndim++] = dim;
    } while (TYPE_CODE(ftype) == TYPE_CODE_ARRAY);

    /* Reduce typedefs of the target */
    if (TYPE_CODE(ftype) == TYPE_CODE_TYPEDEF) {
      const char *ttypename = TYPE_NAME(ftype);
      if (ttypename)
	myDict_SetCharChar(item, "typedef", ttypename);
      CHECK_TYPEDEF(ftype);
    }

    do_ftype(ftype, item);
    PyObject *pdims = PyList_New(0);
    for (i=0; i < ndim; i++) {
      v = PyInt_FromLong(dims[i]);
      PyList_Append(pdims, v);
      Py_DECREF(v);
    }

    PyDict_SetItemString(item, "dims", pdims);
    Py_DECREF(pdims);
    break;
  default:
    myDict_SetCharChar(item, "basetype", TYPE_NAME(ftype));
   break;
  }
  /* Set CODE_TYPE. For arrays and typedefs it should already be
     reduced (we detect array by dims, and we are not interested
     in typedef. But for pointers we are interested both in
     original CODE_TYPE (pointer) and target type (when all
     stars are removed)
  */
  v = PyInt_FromLong(TYPE_CODE(ftype));
  PyDict_SetItemString(item, "codetype", v);
  Py_DECREF(v);

  v = PyInt_FromLong(TYPE_LENGTH(ftype));
  PyDict_SetItemString(item, "typelength", v);
  Py_DECREF(v);

}

static void
do_func(struct type *type, PyObject *pitem) {
  int nfields =   TYPE_NFIELDS(type);
  int i;
  char buf[256];

  PyObject *body = PyList_New(0);
  PyDict_SetItemString(pitem, "prototype", body);

  /* Function return type */
  struct type *return_type= TYPE_TARGET_TYPE(type);
  PyObject *item = PyDict_New();
  PyList_Append(body, item);
  myDict_SetCharChar(item, "fname", "returntype");
  do_ftype(return_type, item);
  Py_DECREF(item);

  for (i=0; i < nfields; i++) {
    struct type *ftype = TYPE_FIELD_TYPE(type, i);
    PyObject *item = PyDict_New();
    PyList_Append(body, item);
    sprintf(buf, "arg%d", i);
    myDict_SetCharChar(item, "fname", buf);

    do_ftype(ftype, item);
    Py_DECREF(item);
  }
  Py_DECREF(body);
}

static void
do_SU(struct type *type, PyObject *pitem) {
  int nfields =   TYPE_NFIELDS(type);
  int i;
  PyObject *v;

  PyObject *body = PyList_New(0);
  PyDict_SetItemString(pitem, "body", body);

  for (i=0; i < nfields; i++) {
    PyObject *item = PyDict_New();
    PyList_Append(body, item);
    struct type *ftype = TYPE_FIELD_TYPE(type, i);
    const char *fname = TYPE_FIELD_NAME(type, i);
    int boffset = TYPE_FIELD_BITPOS(type, i);
    int bsize = TYPE_FIELD_BITSIZE(type, i);

    myDict_SetCharChar(item, "fname", fname);
    if (bsize) {
      v = PyInt_FromLong(bsize);
      PyDict_SetItemString(item, "bitsize", v);
      Py_DECREF(v);
    }

    v = PyInt_FromLong(boffset);
    PyDict_SetItemString(item, "bitoffset", v);
    Py_DECREF(v);

    do_ftype(ftype, item);
    Py_DECREF(item);

  }
  Py_DECREF(body);

}

static void
do_enum(struct type *type, PyObject *pitem) {
  int nfields =   TYPE_NFIELDS(type);
  int i;
  PyObject *n, *v;		/* Name, Value */

  PyObject *edef = PyList_New(0);
  PyDict_SetItemString(pitem, "edef", edef);


  for (i=0; i < nfields; i++) {
    PyObject *item = PyList_New(0);
    //struct type *ftype = TYPE_FIELD_TYPE(type, i);
    const char *fname = TYPE_FIELD_NAME(type, i);
    long bp = TYPE_FIELD_BITPOS (type, i);
    n = PyString_FromString(fname);
    v = PyInt_FromLong(bp);
    PyList_Append(item, n);
    PyList_Append(item, v);
    Py_DECREF(n);
    Py_DECREF(v);

    PyList_Append(edef, item);
    Py_DECREF(item);
  }
  Py_DECREF(edef);
}

PyObject * py_gdb_typeinfo(PyObject *self, PyObject *args) {
  char *typename;
  struct type *type;
  struct expression *expr;
  struct cleanup *old_chain;

  if (!PyArg_ParseTuple(args, "s", &typename)) {
    PyErr_SetString(crashError, "invalid parameter type");	\
    return NULL;
  }
  if (debug > 1)
    printf("gdb_typeinfo(%s)\n", typename);

  GDB2PY_ENTER;

  // ----------------------------------------------
  //printf("GDB: %s\n", typename);
  expr = parse_expression (typename);
  //printf("expr=%p\n", expr);
  old_chain = make_cleanup (free_current_contents, &expr);
  type = ptype_eval (expr);
  //printf("codetype=%p\n", TYPE_CODE(type));

  if (type == NULL)
    my_error_hook();

  PyObject *topdict =  PyDict_New();
  do_ftype(type, topdict);

  do_cleanups (old_chain);
  // ----------------------------------------------

  GDB2PY_EXIT;
  return topdict;
}


PyObject * py_gdb_whatis(PyObject *self, PyObject *args) {
  char *varname;

  struct expression *expr;
  struct value *val;
  struct cleanup *old_chain = NULL;
  struct type *type;

  if (!PyArg_ParseTuple(args, "s", &varname)) {
    PyErr_SetString(crashError, "invalid parameter type");	\
    return NULL;
  }

  if (debug > 1)
    printf("gdb_whatis(%s)\n", varname);

  GDB2PY_ENTER;

  expr = parse_expression (varname);
  old_chain = make_cleanup (free_current_contents, &expr);
  val = evaluate_type (expr);

  type = VALUE_TYPE (val);

  //printf("vartype=%d\n", TYPE_CODE(type));

  PyObject *item = PyDict_New();
  myDict_SetCharChar(item, "fname", varname);


  do_ftype(type, item);

  do_cleanups (old_chain);
  // ----------------------------------------------

  GDB2PY_EXIT;
  return item;
}


// Register enums needed to be used for type-analysis
#define REGISTER_ENUM(name) PyModule_AddObject(m, #name, PyInt_FromLong(name))

void py_gdb_register_enums(PyObject *m) {
  REGISTER_ENUM(TYPE_CODE_PTR);
  REGISTER_ENUM(TYPE_CODE_ARRAY);
  REGISTER_ENUM(TYPE_CODE_STRUCT);
  REGISTER_ENUM(TYPE_CODE_UNION);
  REGISTER_ENUM(TYPE_CODE_ENUM);
  REGISTER_ENUM(TYPE_CODE_FUNC);
  REGISTER_ENUM(TYPE_CODE_INT);
  REGISTER_ENUM(TYPE_CODE_FLT);
  REGISTER_ENUM(TYPE_CODE_VOID);
  REGISTER_ENUM(TYPE_CODE_BOOL);
}

// Some of GDB-6 values
//    TYPE_CODE_PTR = 1           #/* Pointer type */
//    TYPE_CODE_ARRAY = 2         #/* Array type with lower & upper bounds. */
//    TYPE_CODE_STRUCT = 3        #/* C struct or Pascal record */
//    TYPE_CODE_UNION = 4         #/* C union or Pascal variant part */
//    TYPE_CODE_ENUM = 5          #/* Enumeration type */
//    TYPE_CODE_FUNC = 6          #/* Function type */
//    TYPE_CODE_INT = 7           #/* Integer type */
//    TYPE_CODE_FLT = 8
//    TYPE_CODE_VOID = 9
//
