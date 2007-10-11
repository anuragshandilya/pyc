/*
 * Clamav Python Bindings
 *
 * Copyright (c) 2007 Gianluigi Tiesi <sherpya@netfarm.it>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this software; if not, write to the
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <Python.h>
#include <clamav.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef MAX_PATH
#define MAX_PATH 1024
#endif

#ifndef S_ISLNK
#define S_ISLNK(m) (0)
#endif

#ifndef O_BINARY
#define O_BINARY (0)
#endif

#define PYC_VERSION "1.0"

typedef struct _options_t
{
    char *name;
    uint32_t value;
} options_t;

static options_t optlist[] =
{
    { "raw",                 CL_SCAN_RAW                 },
    { "archive",             CL_SCAN_ARCHIVE             },
    { "mail",                CL_SCAN_MAIL                },
    { "ole2",                CL_SCAN_OLE2                },
    { "blockencrypted",      CL_SCAN_BLOCKENCRYPTED      },
    { "html",                CL_SCAN_HTML                },
    { "pe",                  CL_SCAN_PE                  },
    { "blockbroken",         CL_SCAN_BLOCKBROKEN         },
    { "mailurl",             CL_SCAN_MAILURL             },
    { "blockmax",            CL_SCAN_BLOCKMAX            },
    { "algorithmic",         CL_SCAN_ALGORITHMIC         },
    { "domainlist",          CL_SCAN_PHISHING_DOMAINLIST },
    { "phishing_blockssl",   CL_SCAN_PHISHING_BLOCKSSL   },
    { "phishing_blockcloak", CL_SCAN_PHISHING_BLOCKCLOAK },
    { "elf",                 CL_SCAN_ELF                 },
    { "pdf",                 CL_SCAN_PDF                 },

    { NULL,                  0                           }
};

static unsigned int sigs = 0;
static unsigned int vmain = 0, vdaily = 0;
static char dbPath[MAX_PATH + 1] = "";

static struct cl_node  *pyci_root = NULL;
static struct cl_limits pyci_limits;
static uint32_t pyci_options = CL_SCAN_STDOPT;

static PyObject *PycError;
static PyGILState_STATE gstate;

/* Private */
static int pyci_getVersion(const char *name)
{
    char path[MAX_PATH + 1];
    struct cl_cvd *cvd = NULL;
    unsigned int dbver = 0;

    snprintf(path, MAX_PATH, "%s/%s.cvd", dbPath, name);
    path[MAX_PATH] = 0;

    if (access(path, 0) < 0)
    {
        snprintf(path, MAX_PATH, "%s/%s.inc/%s.info", dbPath, name, name);
        path[MAX_PATH] = 0;
    }

    if ((cvd = cl_cvdhead(path)))
    {
        dbver = cvd->version;
        cl_cvdfree(cvd);
    }

    return dbver;
}

static void pyci_getVersions(unsigned int *main, unsigned int *daily)
{
    *main = pyci_getVersion("main");
    *daily = pyci_getVersion("daily");
}

static void pyci_setDBPath(const char *path)
{
    gstate = PyGILState_Ensure();
    strncpy(dbPath, path, MAX_PATH);
    dbPath[MAX_PATH] = 0;
    PyGILState_Release(gstate);
}

static int pyci_loadDB(void)
{
    int ret = 0;

    gstate = PyGILState_Ensure();

    vmain = vdaily = sigs = 0;

    if (pyci_root)
    {
        cl_free(pyci_root);
        pyci_root = NULL;
    }

    if ((ret = cl_load(dbPath, &pyci_root, &sigs, CL_DB_STDOPT)))
    {
        pyci_root = NULL;
        goto cleanup;
    }

    if ((ret = cl_build(pyci_root)))
    {
        cl_free(pyci_root);
        pyci_root = NULL;
        goto cleanup;
    }

    pyci_getVersions(&vmain, &vdaily);

 cleanup:
    PyGILState_Release(gstate);
    return ret;
}

static int pyci_checkDB(void)
{
    unsigned int dbmain = 0, dbdaily = 0;

    if (!pyci_root) return pyci_loadDB();

    pyci_getVersions(&dbmain, &dbdaily);

    if ((dbmain != vmain) || (dbdaily != vdaily))
        return pyci_loadDB();

    return 0;
}

static void pyci_cleanup(void)
{
    if (pyci_root) cl_free(pyci_root);
}

/* Public */
static PyObject *pyc_getVersions(PyObject *self, PyObject *args)
{
    const char *version = NULL;

    if (!(pyci_root && vmain && vdaily))
    {
        PyErr_SetString(PycError, "No database loaded");
        return NULL;
    }

    version = cl_retver();
    return Py_BuildValue("(s,i,i,i)", version, vmain, vdaily, sigs);
}

static PyObject *pyc_setDBPath(PyObject *self, PyObject *args)
{

    char *path = NULL;
    if (!PyArg_ParseTuple(args, "s", &path))
    {
        PyErr_SetString(PycError, "Database path must be a String");
        return NULL;
    }

    pyci_setDBPath(path);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *pyc_getDBPath(PyObject *self, PyObject *args)
{
    return PyString_FromString(dbPath);
}

static PyObject *pyc_loadDB(PyObject *self, PyObject *args)
{
    PyObject *result = NULL;
    unsigned int ret = 0;

    if (!PyArg_UnpackTuple(args, "loadDB", 0, 1, &result))
    {
        PyErr_SetString(PycError, "Invalid arguments");
        return NULL;
    }

    if (result)
    {
        if (PyString_Check(result))
            pyci_setDBPath(PyString_AsString(result));
        else
        {
            PyErr_SetString(PyExc_TypeError, "Database path must be a String");
            return NULL;
        }
    }

    if ((ret = pyci_loadDB()))
    {
        PyErr_SetString(PycError, cl_strerror(ret));
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *pyc_isLoaded(PyObject *self, PyObject *args)
{

    if (pyci_root)
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

static PyObject *pyc_scanDesc(PyObject *self, PyObject *args)
{
    unsigned int ret = 0;
    unsigned long scanned = 0;
    const char *virname = NULL;
    int fd = -1;

    if (!PyArg_ParseTuple(args, "i", &fd))
    {
        PyErr_SetString(PycError, "Invalid argument");
        return NULL;
    }

    if ((ret = pyci_checkDB()))
    {
        PyErr_SetString(PycError, cl_strerror(ret));
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS;
    ret = cl_scandesc(fd, &virname, &scanned, pyci_root, &pyci_limits, pyci_options);
    Py_END_ALLOW_THREADS;

    switch (ret)
    {
        case CL_CLEAN: return Py_BuildValue("(O,s)", Py_False, "CLEAN");
        case CL_VIRUS: return Py_BuildValue("(O,s)", Py_True,  virname);
    }

    PyErr_SetString(PycError, cl_strerror(ret));
    return NULL;
}

static PyObject *pyc_scanFile(PyObject *self, PyObject *args)
{
    PyObject *result = NULL;
    char *filename = NULL;
    struct stat info;
    int fd = -1;

    if (!PyArg_ParseTuple(args, "s", &filename))
    {
        PyErr_SetString(PyExc_TypeError, "Need a String for filename");
        return NULL;
    }

    if (stat(filename, &info) < 0)
    {
        PyErr_SetFromErrno(PycError);
        return NULL;
    }

    if (!(S_ISREG(info.st_mode) || S_ISLNK(info.st_mode)))
    {
        PyErr_SetString(PycError, "Not a regular file");
        return NULL;
    }

    if ((fd = open(filename, O_RDONLY | O_BINARY)) < 0)
    {
        PyErr_SetFromErrno(PycError);
        return NULL;
    }

    result = pyc_scanDesc(self, PyInt_FromInt(fd));
    close(fd);
    return result;
}

static PyObject *pyc_setDebug(PyObject *self, PyObject *args)
{
    cl_debug();
    Py_INCREF(Py_None);
    return Py_None;
}

#define Opt(key) if (!strcmp(opt, #key)) pyci_limits.key = val
static PyObject *pyc_setLimits(PyObject *self, PyObject *args)
{
    PyObject *limits, *keyList, *item, *value, *result;
    int listSize = 0, i;
    char *opt = NULL;
    uint32_t val = 0;

    limits = keyList = item = value = result = NULL;

    if (!PyArg_ParseTuple(args, "O", &limits))
    {
        PyErr_SetString(PyExc_TypeError, "Invalid argument");
        return NULL;
    }

    if (!PyDict_Check(limits))
    {
        PyErr_SetString(PyExc_TypeError, "Limits argument should be a Dictionary");
        return NULL;
    }

    Py_INCREF(Py_None);
    result = Py_None;

    keyList = PyDict_Keys(limits);
    listSize = PyList_Size(keyList);

    for (i = 0; i < listSize; i++)
    {
        item = PyList_GetItem(keyList, i);
        value = PyDict_GetItem(limits, item);

        if (!(PyString_Check(item) && PyInt_Check(value)))
        {
            PyErr_SetString(PyExc_TypeError, "Invalid input");
            result = NULL;
            break;
        }

        opt = PyString_AsString(item);
        val = PyInt_AsLong(value);

        Opt(maxreclevel);
        else Opt(maxfiles);
        else Opt(maxmailrec);
        else Opt(maxratio);
        else Opt(archivememlim);
        else
        {
            PyErr_SetString(PycError, "Invalid option");
            result = NULL;
            break;
        }
    }

    if (result != Py_None) { Py_DECREF(Py_None); }
    return result;
}

#define DictSetItem(key) PyDict_SetItem(limits, PyString_FromString(#key), PyInt_FromLong(pyci_limits.key))
static PyObject *pyc_getLimits(PyObject *self, PyObject *args)
{
    PyObject *limits = PyDict_New();

    if (!limits)
    {
        PyErr_SetString(PyExc_RuntimeError, "Cannot allocate a Dictionary");
        return NULL;
    }

    DictSetItem(maxreclevel);
    DictSetItem(maxfiles);
    DictSetItem(maxmailrec);
    DictSetItem(maxratio);
    DictSetItem(archivememlim);
    return limits;
}

static PyObject *pyc_setOption(PyObject *self, PyObject *args)
{
    char *option = NULL;
    uint32_t value = 0;
    int i;

    if (!PyArg_ParseTuple(args, "si", &option, &value))
    {
        PyErr_SetString(PyExc_TypeError, "Invalid input");
        return NULL;
    }

    for (i = 0; optlist[i].name; i++)
    {
        if (strcmp(option, optlist[i].name)) continue;

        if (value)
            pyci_options |= optlist[i].value;
        else
            pyci_options &= ~optlist[i].value;
        break;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *pyc_getOptions(PyObject *self, PyObject *args)
{
    int i;
    PyObject *list = PyList_New(0);

    if (!list)
    {
        PyErr_SetString(PyExc_RuntimeError, "Cannot allocate a List");
        return NULL;
    }

    for (i = 0; optlist[i].name; i++)
        if (pyci_options & optlist[i].value)
            PyList_Append(list, PyString_FromString(optlist[i].name));

    return list;
}

/* Methods Table */
static PyMethodDef pycMethods[] =
{
    { "getVersions", pyc_getVersions, METH_VARARGS, "Get clamav and database versions"    },
    { "setDBPath",   pyc_setDBPath,   METH_VARARGS, "Set path of virus database"          },
    { "getDBPath",   pyc_getDBPath,   METH_VARARGS, "Get path of virus database"          },
    { "loadDB",      pyc_loadDB,      METH_VARARGS|METH_KEYWORDS, "Load a virus database" },
    { "isLoaded",    pyc_isLoaded,    METH_VARARGS, "Check if db is loaded or not"        },
    { "scanDesc",    pyc_scanDesc,    METH_VARARGS, "Scan a file descriptor"              },
    { "scanFile",    pyc_scanFile,    METH_VARARGS, "Scan a file"                         },
    { "setDebug",    pyc_setDebug,    METH_VARARGS, "Enable libclamav debug messages"     },
    { "setLimits",   pyc_setLimits,   METH_VARARGS, "Set engine limits"                   },
    { "getLimits",   pyc_getLimits,   METH_VARARGS, "Get engine limits as a Dictionary"   },
    { "setOption",   pyc_setOption,   METH_VARARGS, "Enable/Disable scanning options"     },
    { "getOptions",  pyc_getOptions,  METH_VARARGS, "Get a list of enabled options"       },
    { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC
initpyc(void)
{
    PyObject *module = NULL, *dict = NULL;
    module = Py_InitModule("pyc", pycMethods);
    dict = PyModule_GetDict(module);

    PycError = PyErr_NewException("pyc.error", NULL, NULL);
    PyDict_SetItemString(dict, "error", PycError);

    PyDict_SetItemString(dict, "__version__", PyString_FromString(PYC_VERSION));

    /* Internal stuff */
    dbPath[0] = 0;
    strncat(dbPath, cl_retdbdir(), MAX_PATH);
    dbPath[MAX_PATH] = 0;

    /* set up archive limits */
    memset(&pyci_limits, 0, sizeof(pyci_limits));

    pyci_limits.maxreclevel   =   8;      /* maximum recursion level for archives */
    pyci_limits.maxfiles      =   0;      /* maximum number of files to be scanned within a single archive */
    pyci_limits.maxmailrec    =  64;      /* maximum recursion level for mail files */
    pyci_limits.maxratio      = 250;      /* maximum compression ratio */
    pyci_limits.archivememlim =   0;      /* limit memory usage for some unpackers */

    /* compressed files larger than this limit */
    pyci_limits.maxfilesize = 10 * (1 << 20); /* 10 mb */

    atexit(pyci_cleanup); /* I need to free pyci_root */
}

int main(int argc, char *argv[])
{
    /* Pass argv[0] to the Python interpreter */
    Py_SetProgramName(argv[0]);

    /* Initialize the Python interpreter.  Required. */
    Py_Initialize();

    /* Add a static module */
    initpyc();
    return 0;
}
