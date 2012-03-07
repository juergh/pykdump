#if PY_MAJOR_VERSION >= 3
  #define EMPTYS (L"")
  #define PyString_FromString PyUnicode_FromString
  #define evalPyObject PyObject
  #define argvType (wchar_t **)
  #define PyString_AsString(a) PyBytes_AS_STRING(PyUnicode_AsLatin1String(a))
  #define PyString_FromStringAndSize PyUnicode_FromStringAndSize
  #define PyInt_FromLong PyLong_FromLong
  #define PyInt_AsLong PyLong_AsLong
  #define PyInt_Check PyLong_Check
#else
  #define EMPTYS ("")
  #define evalPyObject PyCodeObject
  #define argvType (char **)
#endif
