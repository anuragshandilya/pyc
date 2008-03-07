/*
 * Clamav Python Bindings
 *
 * Copyright (c) 2007-2008 Gianluigi Tiesi <sherpya@netfarm.it>
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
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifdef _WIN32
#define R_OK 4
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif

#ifdef _MSC_VER
typedef unsigned __int64 uint64_t;
typedef signed   __int64 int64_t;
typedef unsigned __int32 uint32_t;
typedef signed   __int32 int32_t;
typedef unsigned __int16 uint16_t;
typedef signed   __int16 int16_t;
typedef unsigned __int8  uint8_t;
typedef signed   __int8  int8_t;
#endif

#ifndef MAX_PATH
#define MAX_PATH 1024
#endif

#ifndef S_ISLNK
#define S_ISLNK(m) (0)
#endif

#ifndef O_BINARY
#define O_BINARY (0)
#endif

#define PyErr_PycFromErrno(func) \
    PyErr_SetObject(PycError, PyString_FromFormat(#func ": %s", strerror(errno)))

#define PyErr_PycFromClamav(func, ret) \
    PyErr_SetObject(PycError, PyString_FromFormat(#func ": %s", cl_strerror(ret)))

/* #define PYC_DEBUG */

#ifdef PYC_DEBUG
#define pyc_DEBUG(func, fmt, ...) fprintf(stderr, "[PycDEBUG] " #func ": "fmt, ##__VA_ARGS__)
#else
#define pyc_DEBUG(func, fmt, ...)
#endif

#define PYC_VERSION "1.0"

typedef struct _options_t
{
    const char *name;
    const uint32_t value;
} options_t;

static const options_t optlist[] =
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
    { "algorithmic",         CL_SCAN_ALGORITHMIC         },
    { "phishing_blockssl",   CL_SCAN_PHISHING_BLOCKSSL   },
    { "phishing_blockcloak", CL_SCAN_PHISHING_BLOCKCLOAK },
    { "elf",                 CL_SCAN_ELF                 },
    { "pdf",                 CL_SCAN_PDF                 },

    { NULL,                  0                           }
};

static unsigned int sigs = 0;
static unsigned int vmain = 0, vdaily = 0;
static char pyci_dbpath[MAX_PATH + 1] = "";

static struct cl_node  *pyci_root = NULL;
static struct cl_stat  *pyci_dbstat = NULL;
static struct cl_limits pyci_limits;
static uint32_t pyci_options = CL_SCAN_STDOPT;

static PyObject *PycError;
static PyGILState_STATE gstate;

static int pyci_dbstatNew(void);
static void pyci_dbstatFree(void);

/* Private */
static int pyci_getVersion(const char *name)
{
    char path[MAX_PATH + 1];
    struct cl_cvd *cvd = NULL;
    unsigned int dbver = 0;

    snprintf(path, MAX_PATH, "%s/%s.cvd", pyci_dbpath, name);
    path[MAX_PATH] = 0;

    if (access(path, R_OK) < 0)
    {
        snprintf(path, MAX_PATH, "%s/%s.cld", pyci_dbpath, name, name);
        path[MAX_PATH] = 0;
    }

    if (access(path, R_OK) < 0) return dbver;

    if ((cvd = cl_cvdhead(path)))
    {
        dbver = cvd->version;
        cl_cvdfree(cvd);
    }

    return dbver;
}

static void pyci_getVersions(unsigned int *main, unsigned int *daily)
{
    gstate = PyGILState_Ensure();
    *main = pyci_getVersion("main");
    *daily = pyci_getVersion("daily");
    PyGILState_Release(gstate);
}

static void pyci_setDBPath(const char *path)
{
    gstate = PyGILState_Ensure();
    strncpy(pyci_dbpath, path, MAX_PATH);
    pyci_dbpath[MAX_PATH] = 0;
    if (pyci_root) cl_free(pyci_root);
    pyci_root = NULL;
    pyci_dbstatFree();
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

    pyc_DEBUG(pyci_loadDB, "Loading db from %s\n", pyci_dbpath);

    if ((ret = cl_load(pyci_dbpath, &pyci_root, &sigs, CL_DB_STDOPT)))
    {
        pyci_root = NULL;
        pyc_DEBUG(pyci_loadDB, "cl_load() failed %s\n", cl_strerror(ret));
        goto cleanup;
    }

    if ((ret = cl_build(pyci_root)))
    {
        cl_free(pyci_root);
        pyci_root = NULL;
        pyc_DEBUG(pyci_loadDB, "cl_build() failed %s\n", cl_strerror(ret));
        goto cleanup;
    }

    ret = pyci_dbstatNew();
 cleanup:
    PyGILState_Release(gstate);
    if (!ret) pyci_getVersions(&vmain, &vdaily);
    return ret;
}

static void pyci_dbstatFree(void)
{
    if (!pyci_dbstat) return;
    cl_statfree(pyci_dbstat);
    PyMem_Free(pyci_dbstat);
    pyci_dbstat = NULL;
}

static int pyci_dbstatNew(void)
{
    int ret;
    if (pyci_dbstat) pyci_dbstatFree();

    if (!(pyci_dbstat = PyMem_Malloc(sizeof(pyci_dbstat))))
    {
        pyc_DEBUG(pyci_dbstatNew, "Out of memory\n");
        return CL_EMEM;
    }

    pyc_DEBUG(pyci_dbstatNew, "Calling cl_statinidir() using %s\n", pyci_dbpath);
    if ((ret = cl_statinidir(pyci_dbpath, pyci_dbstat)))
    {
        pyc_DEBUG(pyci_dbstatNew, "cl_statinidir() failed %s\n", cl_strerror(ret));
        PyMem_Free(pyci_dbstat);
        return ret;
    }
    return CL_SUCCESS;
}

static int pyci_checkAndLoadDB(void)
{
    int ret;

    if (!pyci_dbstat && (ret = pyci_dbstatNew()))
        return ret;

    switch ((ret = cl_statchkdir(pyci_dbstat)))
    {
        case 1: /* needs to be reloaded */
            pyc_DEBUG(pyci_checkAndLoadDB, "virus db needs to be reloaded\n");
            break;
        case CL_SUCCESS:
            pyc_DEBUG(pyci_checkAndLoadDB, "virus db is up to date\n");
            return CL_SUCCESS;
        default:
            pyc_DEBUG(pyci_checkAndLoadDB, "cl_statchkdir() failed %s\n", cl_strerror(ret));
            return ret;
    }

    if ((ret = pyci_loadDB()))
        return ret;

    return CL_SUCCESS;
}

static void pyci_cleanup(void)
{
    pyci_dbstatFree();
    if (pyci_root) cl_free(pyci_root);
}

/* Public */
static PyObject *pyc_getVersions(PyObject *self, PyObject *args)
{
    const char *version = NULL;

    if (!pyci_root)
    {
        PyErr_SetString(PycError, "pyc_getVersions: No database loaded");
        return NULL;
    }

    version = cl_retver();
    return Py_BuildValue("(s,i,i,i)", version, vmain, vdaily, sigs);
}

static PyObject *pyc_setDBPath(PyObject *self, PyObject *args)
{
    char *path = NULL;
    struct stat dp;

    if (!PyArg_ParseTuple(args, "s", &path))
    {
        PyErr_SetString(PycError, "pyc_setDBPath: Database path must be a String");
        return NULL;
    }

    if (stat(path, &dp) < 0)
    {
        PyErr_PycFromErrno(pyc_scanDesc);
        return NULL;
    }

    pyci_setDBPath(path);
    Py_RETURN_NONE;
}

static PyObject *pyc_getDBPath(PyObject *self, PyObject *args)
{
    return PyString_FromString(pyci_dbpath);
}

static PyObject *pyc_loadDB(PyObject *self, PyObject *args)
{
    PyObject *result = NULL;
    unsigned int ret = 0;

    if (!PyArg_UnpackTuple(args, "loadDB", 0, 1, &result))
    {
        PyErr_SetString(PycError, "pyc_loadDB: Invalid arguments");
        return NULL;
    }

    if (result)
    {
        if (PyString_Check(result))
            pyci_setDBPath(PyString_AsString(result));
        else
        {
            PyErr_SetString(PyExc_TypeError, "pyc_loadDB: Database path must be a String");
            return NULL;
        }
    }

    if ((ret = pyci_checkAndLoadDB()))
    {
        PyErr_PycFromClamav(pyc_loadDB, ret);
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *pyc_isLoaded(PyObject *self, PyObject *args)
{
    if (pyci_root)
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

/* Warning passing fd on windows works only if the crt used by python is
   the same used to compile libclamav */
static PyObject *pyc_scanDesc(PyObject *self, PyObject *args)
{
    unsigned int ret = 0;
    unsigned long scanned = 0;
    const char *virname = NULL;
    int fd = -1;

    if (!PyArg_ParseTuple(args, "i", &fd) || (fd < 0))
    {
        PyErr_SetString(PycError, "pyc_scanDesc: Invalid arguments");
        return NULL;
    }

    /* FIXME: add a param to autocheck / time based check of the db */
    if (!pyci_root && (ret = pyci_loadDB()))
    {
        PyErr_PycFromErrno(pyc_scanDesc);
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

    PyErr_PycFromClamav(pyc_ScanDesc, ret);
    return NULL;
}

static PyObject *pyc_scanFile(PyObject *self, PyObject *args)
{
    char *filename = NULL;
    struct stat info;
    PyObject *result = NULL;
    int fd = -1;

    if (!PyArg_ParseTuple(args, "s", &filename))
    {
        PyErr_SetString(PyExc_TypeError, "pyc_scanFile: A string is needed for the filename");
        return NULL;
    }

    if (stat(filename, &info) < 0)
    {
        PyErr_PycFromErrno(pyc_scaFile);
        return NULL;
    }

    if (!(S_ISREG(info.st_mode) || S_ISLNK(info.st_mode)))
    {
        PyErr_SetString(PycError, "pyc_scanFile: Not a regular file");
        return NULL;
    }

    if ((fd = open(filename, O_RDONLY | O_BINARY)) < 0)
    {
        PyErr_PycFromErrno(pyc_scanFile);
        return NULL;
    }

    result = pyc_scanDesc(self, Py_BuildValue("(i)", fd));
    close(fd);
    return result;
}

static PyObject *pyc_setDebug(PyObject *self, PyObject *args)
{
    cl_debug();
    Py_RETURN_NONE;
}

#define Opt(key) if (!strcmp(opt, #key)) pyci_limits.##key = val
static PyObject *pyc_setLimits(PyObject *self, PyObject *args)
{
    PyObject *limits, *keyList, *item, *value, *result;
    int listSize = 0, i;
    char *opt = NULL;
    uint32_t val = 0;

    limits = keyList = item = value = result = NULL;

    if (!PyArg_ParseTuple(args, "O", &limits))
    {
        PyErr_SetString(PyExc_TypeError, "pyc_setLimits: Invalid arguments");
        return NULL;
    }

    if (!PyDict_Check(limits))
    {
        PyErr_SetString(PyExc_TypeError, "pyc_setLimits: A Dictionary is needed to set limits");
        return NULL;
    }

    Py_INCREF(Py_None);
    result = Py_None;

    keyList = PyDict_Keys(limits);
    listSize = PyList_Size(keyList);

    gstate = PyGILState_Ensure();

    for (i = 0; i < listSize; i++)
    {
        item = PyList_GetItem(keyList, i);
        value = PyDict_GetItem(limits, item);

        if (!(PyString_Check(item) && PyInt_Check(value)))
        {
            PyErr_SetString(PyExc_TypeError, "pyc_setLimits: Invalid key pair while parsing limits (arguments should be String: Int)");
            result = NULL;
            break;
        }

        opt = PyString_AsString(item);
        val = PyInt_AsLong(value);

        Opt(maxscansize);
        else Opt(maxfilesize);
        else Opt(maxreclevel);
        else Opt(maxfiles);
        else Opt(archivememlim);
        else
        {
            PyErr_SetString(PycError, "pyc_setLimits: Invalid option specified");
            result = NULL;
            break;
        }
    }

    PyGILState_Release(gstate);

    if (result != Py_None) { Py_DECREF(Py_None); }
    return result;
}

#define DictSetItem(key) PyDict_SetItem(limits, PyString_FromString(#key), PyInt_FromLong(pyci_limits.key))
static PyObject *pyc_getLimits(PyObject *self, PyObject *args)
{
    PyObject *limits = PyDict_New();

    if (!limits)
    {
        PyErr_SetString(PyExc_RuntimeError, "pyc_getLimits: Cannot allocate memory for the Dictionary");
        return NULL;
    }

    DictSetItem(maxscansize);
    DictSetItem(maxfilesize);
    DictSetItem(maxreclevel);
    DictSetItem(maxfiles);
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
        PyErr_SetString(PyExc_TypeError, "pyc_setOption: Invalid arguments");
        return NULL;
    }

    gstate = PyGILState_Ensure();

    for (i = 0; optlist[i].name; i++)
    {
        if (strcmp(option, optlist[i].name)) continue;

        if (value)
            pyci_options |= optlist[i].value;
        else
            pyci_options &= ~optlist[i].value;
        break;
    }

    PyGILState_Release(gstate);

    Py_RETURN_NONE;
}

static PyObject *pyc_getOptions(PyObject *self, PyObject *args)
{
    int i;
    PyObject *list = PyList_New(0);

    if (!list)
    {
        PyErr_SetString(PyExc_RuntimeError, "pyc_getOptions: Cannot allocate memory for the List");
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
    { "setDBPath",   pyc_setDBPath,   METH_VARARGS, "Set path for virus database"         },
    { "getDBPath",   pyc_getDBPath,   METH_VARARGS, "Get path for virus database"         },
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
    strncat(pyci_dbpath, cl_retdbdir(), MAX_PATH);
    pyci_dbpath[MAX_PATH] = 0;

    /* set up archive limits */
    pyci_limits.maxscansize   = 150 * (1 << 20);    /* 150 mb : during the scanning of archives this size will never be exceeded */
    pyci_limits.maxfilesize   = 100 * (1 << 20);    /* 100 mb : compressed files will only be decompressed and scanned up to this size */
    pyci_limits.maxreclevel   = 15;                  /* maximum recursion level for archives */
    pyci_limits.maxfiles      = 10000;               /* maximum number of files to be scanned within a single archive */
    pyci_limits.archivememlim = 0;                   /* limit memory usage for some unpackers */

    Py_AtExit(pyci_cleanup); /* I need to free pyci_root */
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
