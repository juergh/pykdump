#include <Python.h>

#include "defs.h"
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

extern PyObject *crashError;
static void ptype_command (char *typename, int from_tty);
static void whatis_exp (char *exp, int show);

static sigjmp_buf eenv;

typedef NORETURN void (*ERROR_HOOK_TYPE) (void) ATTR_NORETURN;
static ERROR_HOOK_TYPE old_error_hook;



static void my_cleanupsnp() {
  error_hook = (ERROR_HOOK_TYPE) old_error_hook;
  //printf("mycleanupnp\n");
  
}

static void
my_error_hooknp(void)  {
  //printf("Error hook\n");

  do_cleanups(NULL);
  my_cleanupsnp();
  longjmp(eenv, 1);
} 


#define GDB2PY_ENTERNP \
  do { \
    old_error_hook = (ERROR_HOOK_TYPE) error_hook;	\
    error_hook = (ERROR_HOOK_TYPE) my_error_hooknp;	\
    if (setjmp(eenv)) { \
      PyErr_SetString(crashError, "experimental error");\
      return NULL; \
    } \
  } while (0)
    

#define GDB2PY_EXITNP \
  do { \
    my_cleanupsnp(); \
  } while (0)





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


static void
do_ftype(struct type *ftype, PyObject *item) {
  char *tagname = TYPE_TAG_NAME(ftype);
  struct type *range_type;
  struct type *tmptype;

  char buf[246];

  int i;
  
  int stars = 0;
  int dims[4] = {0,0,0,0};
  int ndim = 0;

  
  switch (TYPE_CODE(ftype)) {
  case TYPE_CODE_STRUCT:
    if (tagname != NULL) {
      sprintf(buf, "struct %s", tagname);
    } else {
      sprintf(buf, "(embedded struct)");
    }
    PyDict_SetItem(item, PyString_FromString("basetype"),
		   PyString_FromString(buf));
    break;
  case TYPE_CODE_UNION:
    if (tagname != NULL) {
      sprintf(buf, "union %s", tagname);
    } else{
      sprintf(buf, "(embedded union)");
    }
    PyDict_SetItem(item, PyString_FromString("basetype"),
		   PyString_FromString(buf));
    break;
  case TYPE_CODE_ENUM:
    if (tagname != NULL) {
      sprintf(buf, "enum %s", tagname);
    }
    PyDict_SetItem(item, PyString_FromString("basetype"),
		   PyString_FromString(buf));
    break;
  case TYPE_CODE_PTR:
    tmptype = ftype;
    do {
      stars++;
    } while (TYPE_CODE(tmptype = TYPE_TARGET_TYPE(tmptype)) == TYPE_CODE_PTR);

    if (TYPE_CODE(tmptype) == TYPE_CODE_TYPEDEF)
      CHECK_TYPEDEF(tmptype);
    do_ftype(tmptype, item);
    PyDict_SetItem(item, PyString_FromString("stars"),
		   PyInt_FromLong(stars));
    PyDict_SetItem(item, PyString_FromString("ptrbasetype"),
		 PyInt_FromLong(TYPE_CODE(tmptype)));
    break;
  case TYPE_CODE_FUNC:
    PyDict_SetItem(item, PyString_FromString("basetype"),
		   PyString_FromString("(func)"));
    break;
  case TYPE_CODE_TYPEDEF:
    CHECK_TYPEDEF(ftype);
    do_ftype(ftype, item);
    break;
  case TYPE_CODE_INT:
    PyDict_SetItem(item, PyString_FromString("uint"),
		   PyInt_FromLong(TYPE_UNSIGNED(ftype)));
    PyDict_SetItem(item, PyString_FromString("basetype"),
		   PyString_FromString(TYPE_NAME(ftype)));
    break;
  case TYPE_CODE_ARRAY:
    /* Multidimensional C-arrays are visible as arrays of arrays.
       We need to recurse or iterate to obtain all dimensions
    */
    do {
      range_type = TYPE_FIELD_TYPE (ftype, 0);
      ftype= TYPE_TARGET_TYPE(ftype);
      dims[ndim++] = TYPE_FIELD_BITPOS(range_type, 1)+1;
    } while (TYPE_CODE(ftype) == TYPE_CODE_ARRAY);
    do_ftype(ftype, item);
    printf(" ");
    PyObject *pdims = PyList_New(0);
    for (i=0; i < ndim; i++)
      PyList_Append(pdims, PyInt_FromLong(dims[i]));
    
    PyDict_SetItem(item, PyString_FromString("dims"), pdims);
    break;
  default:
    PyDict_SetItem(item, PyString_FromString("basetype"),
		   PyString_FromString(TYPE_NAME(ftype)));
   break;
  }
  /* Set CODE_TYPE. For arrays and typedefs it should already be
     reduced (we detect array by dims, and we are not interested
     in typedef. But for pointers we are interested both in
     original CODE_TYPE (pointer) and target type (when all
     stars are removed)
  */
  PyDict_SetItem(item, PyString_FromString("codetype"),
		 PyInt_FromLong(TYPE_CODE(ftype)));
  
}


void
toplevel(struct type *type, PyObject *list) {
  int nfields =   TYPE_NFIELDS(type);
  int i;
  for (i=0; i < nfields; i++) {
    PyObject *item = PyDict_New();
    PyList_Append(list, item);
    struct type *ftype = TYPE_FIELD_TYPE(type, i);
    char *fname = TYPE_FIELD_NAME(type, i);
    int boffset = TYPE_FIELD_BITPOS(type, i);
    int bsize = TYPE_FIELD_BITSIZE(type, i);

    PyDict_SetItem(item, PyString_FromString("fname"),
		   PyString_FromString(fname));
    do_ftype(ftype, item);
  }
 
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

  GDB2PY_ENTERNP;

  // ----------------------------------------------
  expr = parse_expression (typename);
  old_chain = make_cleanup (free_current_contents, &expr);
  type = ptype_eval (expr);
  //myptype(type, 0);

  PyObject *toplist = PyList_New(0);
  PyList_Append(toplist, PyString_FromString(typename));
  toplevel(type, toplist);
  
  do_cleanups (old_chain);
  // ----------------------------------------------

  GDB2PY_EXITNP;
  return toplist;
}


PyObject * py_gdb_mywhatis(PyObject *self, PyObject *args) {
  char *varname;

  struct expression *expr;
  struct value *val;
  struct cleanup *old_chain = NULL;
  struct type *type;


  if (!PyArg_ParseTuple(args, "s", &varname)) {
    PyErr_SetString(crashError, "invalid parameter type");	\
    return NULL;
  }

  GDB2PY_ENTERNP;

  expr = parse_expression (varname);
  old_chain = make_cleanup (free_current_contents, &expr);
  val = evaluate_type (expr);

  type = VALUE_TYPE (val);

  //printf("vartype=%s\n", typecode2s(TYPE_CODE(type)));

  PyObject *toplist = PyList_New(0);
  PyList_Append(toplist, PyString_FromString("(vartype)"));
  
  PyObject *item = PyDict_New();
  PyDict_SetItem(item, PyString_FromString("fname"),
		 PyString_FromString(varname));
  PyList_Append(toplist, item);


  do_ftype(type, item);

  do_cleanups (old_chain);
  // ----------------------------------------------

  GDB2PY_EXITNP;
  return toplist;
}


// ============== old code doing printing ================
static struct ui_file *ui_file;
static struct ui_file *olduifile;


static void my_cleanups() {
  ui_file_delete (ui_file);
  gdb_stdout = olduifile;
  error_hook = (ERROR_HOOK_TYPE) old_error_hook;
  //printf("mycleanup\n");
  
}

static void
my_error_hook(void)  {
  //printf("Error hook\n");

  do_cleanups(NULL);
  my_cleanups();
  longjmp(eenv, 1);
} 


/* If GDB error was caught, raise Python exception. Cleanup is
   already done in my_error_hook
*/

/* Prepare to run a function calling directly GDB internals. We substitute
 */
#define GDB2PY_ENTER \
  do { \
    ui_file = mem_fileopen (); \
    old_error_hook = (ERROR_HOOK_TYPE) error_hook;	\
    error_hook = (ERROR_HOOK_TYPE) my_error_hook;	\
    olduifile = gdb_stdout; \
    gdb_stdout=  ui_file; \
    if (setjmp(eenv)) { \
      PyErr_SetString(crashError, "experimental error");\
      return NULL; \
    } \
  } while (0)
    

#define GDB2PY_EXIT \
  do { \
    long length;\
    const char *text = ui_file_xstrdup (ui_file, &length); \
    my_cleanups(); \
    return PyString_FromStringAndSize(text, length); \
  } while (0)



PyObject * py_gdb_whatis(PyObject *self, PyObject *args) {
  char *varname;

  if (!PyArg_ParseTuple(args, "s", &varname)) {
    PyErr_SetString(crashError, "invalid parameter type");	\
    return NULL;
  }

  GDB2PY_ENTER;
  
  whatis_exp(varname, -1);

  GDB2PY_EXIT;
}

static const char *typecode2s(int c) {
  static char buf[256];
  switch(c) {
  case TYPE_CODE_PTR:
    return "TYPE_CODE_PTR";
  case TYPE_CODE_ARRAY:
    return "TYPE_CODE_ARRAY";
  case TYPE_CODE_STRUCT:
    return "TYPE_CODE_STRUCT";
  case TYPE_CODE_UNION:
    return "TYPE_CODE_UNION";
  case TYPE_CODE_ENUM:
    return "TYPE_CODE_ENUM";
  case TYPE_CODE_FUNC:
    return "TYPE_CODE_FUNC";
  case TYPE_CODE_INT:
    return "TYPE_CODE_INT";
  case TYPE_CODE_VOID:
    return "TYPE_CODE_VOID";
  case TYPE_CODE_TYPEDEF:
    return "TYPE_CODE_TYPEDEF";
  default:
    sprintf(buf, "TYPE_CODE_%d", c);
    return buf;
  }
}

static void print_ftype(struct type *ftype) {
  char *tagname = TYPE_TAG_NAME(ftype);
  struct type *range_type;
  struct type *rtype;

  int i;
  
  int stars = 0;
  int dims[4] = {0,0,0,0};
  int ndim = 0;
  
  switch (TYPE_CODE(ftype)) {
  case TYPE_CODE_STRUCT:
    if (tagname != NULL) {
      printf("struct %s", tagname);
    } else {
      printf("(embedded struct)");
    }
    break;
  case TYPE_CODE_UNION:
    if (tagname != NULL) {
      printf("union %s", tagname);
    } else{
      printf("(embedded union)");
    }
    break;
  case TYPE_CODE_ENUM:
    if (tagname != NULL) {
      printf("enum %s", tagname);
    }
    break;
  case TYPE_CODE_PTR:
    do {
      stars++;
    } while (TYPE_CODE(ftype = TYPE_TARGET_TYPE(ftype)) == TYPE_CODE_PTR);

    print_ftype(ftype);
    printf(" ");
    for (i=0; i < stars; i++)
      printf("*");
    break;
  case TYPE_CODE_FUNC:
    printf("(func)");
    break;
  case TYPE_CODE_TYPEDEF:
    printf("%s => ", TYPE_NAME(ftype));
    CHECK_TYPEDEF(ftype);
    printf("%s ", typecode2s(TYPE_CODE(ftype))+5);
    print_ftype(ftype);
    break;
  case TYPE_CODE_ARRAY:
    /* Multidimensional C-arrays are visible as arrays of arrays.
       We need to recurse or iterate to obtain all dimensions
    */
    do {
      range_type = TYPE_FIELD_TYPE (ftype, 0);
      ftype= TYPE_TARGET_TYPE(ftype);
      dims[ndim++] = TYPE_FIELD_BITPOS(range_type, 1)+1;
    } while (TYPE_CODE(ftype) == TYPE_CODE_ARRAY);
    print_ftype(ftype);
    printf(" ");
    for (i=0; i < ndim; i++)
      printf("[%d]", dims[i]);
    
    break;
  default:
    printf("%s", TYPE_NAME(ftype));
    break;
  }
}



void
myptype(struct type *type, int indent) {
  int nfields =   TYPE_NFIELDS(type);
  int i;
  char sindent[128];
  strcpy(sindent, "                                                     ");
  sindent[indent] = '\0';
    
  //printf("%snfields=%d\n", sindent, nfields);
  for (i=0; i < nfields; i++) {
    struct type *ftype = TYPE_FIELD_TYPE(type, i);
    char *fname = TYPE_FIELD_NAME(type, i);
    int boffset = TYPE_FIELD_BITPOS(type, i);
    int bsize = TYPE_FIELD_BITSIZE(type, i);
    printf("%si=%2d, %-15s %-11s ",
	   sindent, i, fname, typecode2s(TYPE_CODE(ftype))+5);
    print_ftype(ftype);
    puts("");
  }
}


static void
ptype_command (char *typename, int from_tty)
{
  struct type *type;
  struct expression *expr;
  struct cleanup *old_chain;

  expr = parse_expression (typename);
  old_chain = make_cleanup (free_current_contents, &expr);
  type = ptype_eval (expr);
  if (type != NULL)    {
      type_print (type, "", gdb_stdout, 1);
      printf_filtered ("\n");
      do_cleanups (old_chain);
    }  else   {
      /* User did "ptype <symbolname>" */
      do_cleanups (old_chain);
      whatis_exp (typename, 1);
    }

}


static void
whatis_exp (char *exp, int show)
{
  struct expression *expr;
  struct value *val;
  struct cleanup *old_chain = NULL;
  struct type *type;


  expr = parse_expression (exp);
  old_chain = make_cleanup (free_current_contents, &expr);
  val = evaluate_type (expr);

  type = VALUE_TYPE (val);

  type_print (type, "", gdb_stdout, show);

  /*  I don't quite understand why the next line is needed - alexs */
  printf_filtered ("\n");

  if (exp)
    do_cleanups (old_chain);
}

PyObject * py_gdb_ptype(PyObject *self, PyObject *args) {
  char *varname;

  if (!PyArg_ParseTuple(args, "s", &varname)) {
    PyErr_SetString(crashError, "invalid parameter type");	\
    return NULL;
  }

  GDB2PY_ENTER;
  
  ptype_command(varname, 0);

  GDB2PY_EXIT;
}
