/*
 * acefile - read/test/extract ACE 1.0 and 2.0 archives in pure python
 * Copyright (C) 2017-2019, Daniel Roethlisberger <daniel@roe.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * NOTE:  The ACE archive format and ACE compression and decompression
 * algorithms have been designed by Marcel Lemke.  The above copyright
 * notice and license does not constitute a claim of intellectual property
 * over ACE technology beyond the copyright of this python implementation.
 */

/*
 * Optional fast implementation of BitStream class in c.
 * For class documentation, see python implementation in acefile.py.
 */

#include <Python.h>

#include "acebitstream.h"

static size_t
filelike_read(void *ctx, char *buf, size_t n)
{
	size_t ret, i;
	char *p;
	PyObject *arglist;
	PyObject *method;
	PyObject *buffer;
	PyObject *f = ctx;

	method = PyObject_GetAttrString(f, (char*)"read");
	if (method == NULL)
		return 0;
	arglist = Py_BuildValue("(k)", n);
	if (arglist == NULL)
		return 0;
	buffer = PyObject_CallObject(method, arglist);
	Py_DECREF(arglist);
	if (buffer == NULL)
		return 0;
	ret = PyBytes_Size(buffer);
	if (ret % 4) {
		Py_DECREF(buffer);
		PyErr_SetString(PyExc_ValueError,
		                "Truncated 32-bit word from file-like object");
		return 0;
	}
	p = PyBytes_AsString(buffer);
	if (p == NULL) {
		Py_DECREF(buffer);
		return 0;
	}
#if BIG_ENDIAN_SWAP
	for (i = 0; i < ret; i += 4) {
		buf[i]   = p[i+3];
		buf[i+1] = p[i+2];
		buf[i+2] = p[i+1];
		buf[i+3] = p[i];
	}
#else /* LITTLE_ENDIAN_SWAP */
	for (i = 0; i < ret; i++) {
		buf[i] = p[i];
	}
#endif
	Py_DECREF(buffer);
	return ret;
}

typedef struct {
	PyObject_HEAD
	acebitstream_ctx_t *ctx;
} BitStream;

static void
BitStream_dealloc(BitStream *self)
{
	if (self->ctx) {
		Py_DECREF((PyObject*)self->ctx->read_ctx);
		acebitstream_free(self->ctx);
	}
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
BitStream_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	BitStream *self;

	self = (BitStream*)type->tp_alloc(type, 0);
	if (self == NULL)
		return NULL;
	self->ctx = NULL;
	return (PyObject*)self;
}

static int
BitStream_init(BitStream *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"f", "bufsz", NULL};
	PyObject *f;
	size_t bufsz = 131072;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|I", kwlist, &f, &bufsz))
		return -1;
	Py_INCREF(f);
	self->ctx = acebitstream_new(filelike_read, f, bufsz);
	if (PyErr_Occurred())
		return -1;
	return 0;
}

static PyObject *
BitStream_peek_bits(BitStream *self, PyObject *args)
{
	size_t ret;
	unsigned int n = 0;

	if (!PyArg_ParseTuple(args, "I", &n))
		return NULL;
	if (n > 31) {
		PyErr_SetString(PyExc_ValueError,
		                "Cannot peek more than 31 bits");
		return NULL;
	}

	ret = acebitstream_peek_bits(self->ctx, n);
	if (PyErr_Occurred())
		return NULL;
	return PyLong_FromLong(ret);
}

static PyObject *
BitStream_skip_bits(BitStream *self, PyObject *args)
{
	size_t ret;
	unsigned int n = 0;

	if (!PyArg_ParseTuple(args, "I", &n))
		return NULL;
	if (n > 31) {
		PyErr_SetString(PyExc_ValueError,
		                "Cannot skip more than 31 bits");
		return NULL;
	}

	ret = acebitstream_skip_bits(self->ctx, n);
	if (PyErr_Occurred())
		return NULL;
	if (ret == ACEBITSTREAM_EOF) {
		PyErr_SetString(PyExc_EOFError,
		                "Cannot skip bits beyond EOF");
		return NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
BitStream_read_bits(BitStream *self, PyObject *args)
{
	size_t ret;
	unsigned int n = 0;

	if (!PyArg_ParseTuple(args, "I", &n))
		return NULL;
	if (n > 31) {
		PyErr_SetString(PyExc_ValueError,
		                "Cannot read more than 31 bits");
		return NULL;
	}

	ret = acebitstream_read_bits(self->ctx, n);
	if (PyErr_Occurred())
		return NULL;
	if (ret == ACEBITSTREAM_EOF) {
		PyErr_SetString(PyExc_EOFError,
		                "Cannot read bits beyond EOF");
		return NULL;
	}
	return PyLong_FromLong(ret);
}

static PyMethodDef BitStream_methods[] = {
	{"peek_bits", (PyCFunction)BitStream_peek_bits, METH_VARARGS, NULL},
	{"skip_bits", (PyCFunction)BitStream_skip_bits, METH_VARARGS, NULL},
	{"read_bits", (PyCFunction)BitStream_read_bits, METH_VARARGS, NULL},
	{NULL}
};

static PyTypeObject BitStreamType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"acebitstream.BitStream",               /* tp_name */
	sizeof(BitStream),                      /* tp_basicsize */
	0,                                      /* tp_itemsize */
	(destructor)BitStream_dealloc,          /* tp_dealloc */
	0,                                      /* tp_print */
	0,                                      /* tp_getattr */
	0,                                      /* tp_setattr */
	0,                                      /* tp_reserved */
	0,                                      /* tp_repr */
	0,                                      /* tp_as_number */
	0,                                      /* tp_as_sequence */
	0,                                      /* tp_as_mapping */
	0,                                      /* tp_hash  */
	0,                                      /* tp_call */
	0,                                      /* tp_str */
	0,                                      /* tp_getattro */
	0,                                      /* tp_setattro */
	0,                                      /* tp_as_buffer */
	Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE, /* tp_flags */
	"BitStream objects",                    /* tp_doc */
	0,                                      /* tp_traverse */
	0,                                      /* tp_clear */
	0,                                      /* tp_richcompare */
	0,                                      /* tp_weaklistoffset */
	0,                                      /* tp_iter */
	0,                                      /* tp_iternext */
	BitStream_methods,                      /* tp_methods */
	0,                                      /* tp_members */
	0,                                      /* tp_getset */
	0,                                      /* tp_base */
	0,                                      /* tp_dict */
	0,                                      /* tp_descr_get */
	0,                                      /* tp_descr_set */
	0,                                      /* tp_dictoffset */
	(initproc)BitStream_init,               /* tp_init */
	0,                                      /* tp_alloc */
	BitStream_new,                          /* tp_new */
};

static struct PyModuleDef acebitstream_module = {
	PyModuleDef_HEAD_INIT,
	"acebitstream",
	NULL,
	-1,
	NULL, NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC
PyInit_acebitstream(void)
{
	PyObject *module;

	BitStreamType.tp_new = PyType_GenericNew;
	if (PyType_Ready(&BitStreamType) < 0)
		return NULL;

	module = PyModule_Create(&acebitstream_module);
	if (module == NULL)
		return NULL;

	Py_INCREF(&BitStreamType);
	PyModule_AddObject(module, "BitStream", (PyObject*)&BitStreamType);

	return module;
}

