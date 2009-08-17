/*
 * parec Python API
 *
 * Copyright (c) Akos FROHNER <akos@frohner.hu> 2009.
 * License: LGPLv2.1
 */

#include <parec.h>
#include <strings.h>
#include <Python.h>

static PyObject *ParecError;

typedef struct {
    PyObject_HEAD
    parec_ctx* ctx;
} Parec;

static void Parec_dealloc(Parec *self)
{
    parec_free(self->ctx);
    self->ob_type->tp_free((PyObject*)self);
}

static PyObject *Parec_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    Parec *self;

    self = (Parec *)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->ctx = parec_new();
        if (self->ctx == NULL) {
            Py_DECREF(self);
            return NULL;
        }
    }

    return (PyObject *)self;
}


static PyObject *Parec_process(Parec *self, PyObject *args)
{
    const char *name;

    if (!PyArg_ParseTuple(args, "s", &name)) {
        // error already set
        return NULL;
    }
    if (parec_process(self->ctx, name)) {
        PyErr_SetString(ParecError, parec_get_error(self->ctx));
        return NULL;
    }
    
    Py_RETURN_NONE;
}

static PyObject *Parec_purge(Parec *self, PyObject *args)
{
    const char *name;

    if (!PyArg_ParseTuple(args, "s", &name)) {
        // error already set
        return NULL;
    }
    if (parec_purge(self->ctx, name)) {
        PyErr_SetString(ParecError, parec_get_error(self->ctx));
        return NULL;
    }
    
    Py_RETURN_NONE;
}

static PyObject *Parec_add_checksum(Parec *self, PyObject *args)
{
    const char *algorithm;
    if (!PyArg_ParseTuple(args, "s", &algorithm)) {
        // error already set
        return NULL;
    }
    if (parec_add_checksum(self->ctx, algorithm)) {
        PyErr_SetString(ParecError, parec_get_error(self->ctx));
        return NULL;
    }
    
    Py_RETURN_NONE;
}

static PyObject *Parec_get_checksums(Parec *self)
{
    int count, i;
    PyObject *checksums = NULL;
    const char *alg = NULL;
    PyObject *algorithm = NULL;

    if ((count = parec_get_checksum_count(self->ctx)) < 0) {
        PyErr_SetString(ParecError, parec_get_error(self->ctx));
        return NULL;
    }
    
    if ((checksums = PyTuple_New(count)) == NULL) {
        return NULL;
    }

    for (i = 0; i < count; i++) {
        if ((alg = parec_get_checksum_name(self->ctx, i)) == NULL) {
            PyErr_SetString(ParecError, parec_get_error(self->ctx));
            Py_DECREF(checksums);
            return NULL;
        }
        if ((algorithm = PyString_FromString(alg)) == NULL) {
            Py_DECREF(checksums);
            return NULL;
        }
        PyTuple_SET_ITEM(checksums, i, algorithm);
    }

    return checksums;
}

static PyObject *Parec_add_exclude_pattern(Parec *self, PyObject *args)
{
    const char *pattern;
    if (!PyArg_ParseTuple(args, "s", &pattern)) {
        // error already set
        return NULL;
    }
    if (parec_add_exclude_pattern(self->ctx, pattern)) {
        PyErr_SetString(ParecError, parec_get_error(self->ctx));
        return NULL;
    }
    
    Py_RETURN_NONE;
}

static PyObject *Parec_get_exclude_patterns(Parec *self)
{
    int count, i;
    PyObject *exclude_patterns = NULL;
    const char *pat = NULL;
    PyObject *pattern = NULL;

    if ((count = parec_get_exclude_count(self->ctx)) < 0) {
        PyErr_SetString(ParecError, parec_get_error(self->ctx));
        return NULL;
    }
    
    if ((exclude_patterns = PyTuple_New(count)) == NULL) {
        return NULL;
    }

    for (i = 0; i < count; i++) {
        if ((pat = parec_get_exclude_pattern(self->ctx, i)) == NULL) {
            PyErr_SetString(ParecError, parec_get_error(self->ctx));
            Py_DECREF(exclude_patterns);
            return NULL;
        }
        if ((pattern = PyString_FromString(pat)) == NULL) {
            Py_DECREF(exclude_patterns);
            return NULL;
        }
        PyTuple_SET_ITEM(exclude_patterns, i, pattern);
    }

    return exclude_patterns;
}

static PyObject *Parec_set_xattr_prefix(Parec *self, PyObject *args)
{
    const char *prefix;
    if (!PyArg_ParseTuple(args, "s", &prefix)) {
        // error already set
        return NULL;
    }
    if (parec_set_xattr_prefix(self->ctx, prefix)) {
        PyErr_SetString(ParecError, parec_get_error(self->ctx));
        return NULL;
    }
    
    Py_RETURN_NONE;
}

static PyObject *Parec_set_method(Parec *self, PyObject *args)
{
    const char *smethod;
    parec_method method;

    if (!PyArg_ParseTuple(args, "s", &smethod)) {
        // error already set
        return NULL;
    }

    if (strcasecmp("default", smethod) == 0) {
        method = PAREC_METHOD_DEFAULT;
    } else 
    if (strcasecmp("check", smethod) == 0) {
        method = PAREC_METHOD_CHECK;
    } else 
    if (strcasecmp("force", smethod) == 0) {
        method = PAREC_METHOD_FORCE;
    } else  {
        PyErr_SetString(ParecError, "unknown method name");
        return NULL;
    }

    if (parec_set_method(self->ctx, method)) {
        PyErr_SetString(ParecError, parec_get_error(self->ctx));
        return NULL;
    }
    
    Py_RETURN_NONE;
}

static PyObject *Parec_get_xattr_values(Parec *self, PyObject *args)
{
    int count, i;
    PyObject *xattr_values = NULL;
    char *value = NULL;
    PyObject *pvalue = NULL;
    const char *algname = NULL;
    const char *name;

    if (!PyArg_ParseTuple(args, "s", &name)) {
        // error already set
        return NULL;
    }

    if ((count = parec_get_checksum_count(self->ctx)) < 0) {
        PyErr_SetString(ParecError, parec_get_error(self->ctx));
        return NULL;
    }
    
    if ((xattr_values = PyDict_New()) == NULL) {
        return NULL;
    }

    for (i = 0; i < count; i++) {
        if ((algname = parec_get_checksum_name(self->ctx, i)) == NULL) {
            PyErr_SetString(ParecError, parec_get_error(self->ctx));
            Py_DECREF(xattr_values);
            return NULL;
        }
        if ((value = parec_get_xattr_value(self->ctx, i, name)) == NULL) {
            PyErr_SetString(ParecError, parec_get_error(self->ctx));
            Py_DECREF(xattr_values);
            return NULL;
        }
        if ((pvalue = PyString_FromString(value)) == NULL) {
            Py_DECREF(xattr_values);
            free(value);
            return NULL;
        }
        free(value);
        if (PyDict_SetItemString(xattr_values, algname, pvalue)) {
            Py_DECREF(xattr_values);
            Py_DECREF(pvalue);
            return NULL;
        }
    }

    return xattr_values;
}

static PyMethodDef Parec_methods[] = {
    {"process", (PyCFunction)Parec_process, METH_VARARGS, 
      "Process a file or directory." },
    {"purge", (PyCFunction)Parec_purge, METH_VARARGS, 
      "Purge a file or directory." },
    {"add_checksum", (PyCFunction)Parec_add_checksum, METH_VARARGS, 
     "Add a checksum algorithm." },
    {"get_checksums", (PyCFunction)Parec_get_checksums, METH_NOARGS, 
     "Returns the checksum algorithms." },
    {"add_exclude_pattern", (PyCFunction)Parec_add_exclude_pattern, METH_VARARGS, 
     "Add a exclude pattern." },
    {"get_exclude_patterns", (PyCFunction)Parec_get_exclude_patterns, METH_NOARGS, 
     "Returns the exclude patterns." },
    {"set_xattr_prefix", (PyCFunction)Parec_set_xattr_prefix, METH_VARARGS, 
     "Set the prefix for the extended attributes." },
    {"set_method", (PyCFunction)Parec_set_method, METH_VARARGS, 
     "Set the calculation method." },
    {"get_xattr_values", (PyCFunction)Parec_get_xattr_values, METH_VARARGS, 
      "Get the extended attributes associated with a file or directory." },
    {NULL, NULL, 0, NULL}
};

static PyTypeObject ParecType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "parec.Parec",             /*tp_name*/
    sizeof(Parec), /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)Parec_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,        /*tp_flags*/
    "Parec objects",           /* tp_doc */
    0,		                   /* tp_traverse */
    0,		                   /* tp_clear */
    0,		                   /* tp_richcompare */
    0,		                   /* tp_weaklistoffset */
    0,		                   /* tp_iter */
    0,		                   /* tp_iternext */
    Parec_methods,             /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,                         /* tp_init */
    0,                         /* tp_alloc */
    Parec_new,                 /* tp_new */
};

static PyMethodDef parec_methods[] = {
    {NULL}
};

PyMODINIT_FUNC
initparec(void)
{
    PyObject* m;

    if (PyType_Ready(&ParecType) < 0)
        return;

    m = Py_InitModule3("parec", parec_methods, "Parallel Recursive Checkums");
    if (NULL == m) return;

    Py_INCREF(&ParecType);
    PyModule_AddObject(m, "Parec", (PyObject *)&ParecType);

    ParecError = PyErr_NewException("parec.ParecError", NULL, NULL);
    Py_INCREF(ParecError);
    PyModule_AddObject(m, "ParecError", ParecError);
}

