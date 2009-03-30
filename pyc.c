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

/* #define PYC_DEBUG */

#include <Python.h>
#include <clamav.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

#ifdef PYC_DEBUG
#undef NDEBUG
#endif

#include <assert.h>

#ifdef _WIN32
#define R_OK 4
#include <windows.h>
#include <io.h>
/* Get some help from clamav win32 specific functions */
extern char *cw_normalizepath(const char *path);
extern int cw_stat(const char *path, struct stat *buf);
extern BOOL cw_fsredirection(BOOL value);
extern BOOL cw_iswow64(void);
#define lstat stat
#define stat(p, b) cw_stat(p, b)
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
#else
#include <inttypes.h>
#endif

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#ifndef S_ISLNK
#define S_ISLNK(m) (0)
#endif

#ifndef O_BINARY
#define O_BINARY (0)
#endif

#undef Py_RETURN_TRUE
#undef Py_RETURN_FALSE
#undef Py_RETURN_NONE

/* Backward compatibility, these macros were added in 2.4 */
#ifndef Py_RETURN_TRUE
#define Py_RETURN_TRUE return Py_INCREF(Py_True), Py_True
#endif

#ifndef Py_RETURN_FALSE
#define Py_RETURN_FALSE return Py_INCREF(Py_False), Py_False
#endif

#ifndef Py_RETURN_NONE
#define Py_RETURN_NONE return Py_INCREF(Py_None), Py_None
#endif

#define PyErr_PycFromErrno(func) \
    PyErr_SetObject(PycError, PyString_FromFormat(#func ": %s", strerror(errno)))

#define PyErr_PycFromClamav(func, ret) \
    PyErr_SetObject(PycError, PyString_FromFormat(#func ": %s", cl_strerror(ret)))


/* msvc6 does not support variadic macros */
#if defined(_MSC_VER) && (_MSC_VER < 1400)
void pyc_DEBUG(void *func, const char *fmt, ...) {}
#else
#ifdef PYC_DEBUG
#define pyc_DEBUG(func, fmt, ...) fprintf(stderr, "[PycDEBUG] " #func ": "fmt, ##__VA_ARGS__)
#else
#define pyc_DEBUG(func, fmt, ...)
#endif
#endif

#define PYC_VERSION "Python ClamAV version 2.0.95"

#define PYC_SELFCHECK_NEVER     0
#define PYC_SELFCHECK_ALWAYS   -1

typedef enum { OPT_NONE = 0, OPT_NUM, OPT_STR } opt_t;

typedef struct _engine_options_t
{
    const char *name;
    const opt_t type;
    char readonly;
    const uint32_t id;
} engine_options_t;

static const engine_options_t engine_options[] =
{
    { "max-scansize",             OPT_NUM,  0,  CL_ENGINE_MAX_SCANSIZE      },
    { "max-filesize",             OPT_NUM,  0,  CL_ENGINE_MAX_FILESIZE      },
    { "max-recursion",            OPT_NUM,  0,  CL_ENGINE_MAX_RECURSION     },
    { "max-files",                OPT_NUM,  0,  CL_ENGINE_MAX_FILES         },
/*
    { "structured-cc-count",      OPT_NUM,  0,  CL_ENGINE_MIN_CC_COUNT      },
    { "structured-ssn-count",     OPT_NUM,  0,  CL_ENGINE_MIN_SSN_COUNT     },
*/
    { "pua-categories",           OPT_STR,  0,  CL_ENGINE_PUA_CATEGORIES    },
    { "db-version",               OPT_NUM,  1,  CL_ENGINE_DB_VERSION        },
    { "db-time",                  OPT_NUM,  1,  CL_ENGINE_DB_TIME           },
    { "ac-only",                  OPT_NUM,  0,  CL_ENGINE_AC_ONLY           },
    { "ac-mindepth",              OPT_NUM,  0,  CL_ENGINE_AC_MINDEPTH       },
    { "ac-maxdepth",              OPT_NUM,  0,  CL_ENGINE_AC_MAXDEPTH       },
    { "tempdir",                  OPT_STR,  0,  CL_ENGINE_TMPDIR            },
    { "leave-temps",              OPT_NUM,  0,  CL_ENGINE_KEEPTMP           },

    { NULL,                       OPT_NONE, 0,  0                           }
};

typedef struct _scan_options_t
{
    const char *name;
    const uint32_t id;
} scan_options_t;

static const scan_options_t scan_options[] =
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
static time_t pyci_lastcheck = 0;
static time_t pyci_checktimer = PYC_SELFCHECK_NEVER;

static struct cl_engine *pyci_engine = NULL;
static struct cl_stat  *pyci_dbstat = NULL;
static uint32_t pyci_options = CL_SCAN_STDOPT;

static PyObject *PycError;
static PyGILState_STATE gstate;

static int pyci_dbstatNew(void);
static void pyci_dbstatFree(void);
static void pyci_freeDB(void);

#define pyci_isCompiled (cl_engine_get_num(pyci_engine, CL_ENGINE_DB_OPTIONS, NULL) & CL_DB_COMPILED)

/* Private */
static int pyci_getVersion(const char *name)
{
    char path[MAX_PATH + 1];
    struct cl_cvd *cvd;
    unsigned int dbver = 0;

    snprintf(path, MAX_PATH, "%s/%s.cvd", pyci_dbpath, name);
    path[MAX_PATH] = 0;

    if (access(path, R_OK) < 0)
    {
        snprintf(path, MAX_PATH, "%s/%s.cld", pyci_dbpath, name);
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

static void pyci_freeDB(void)
{
    if (pyci_engine)
        cl_engine_free(pyci_engine);
    pyci_engine = NULL;
}

static void pyci_setDBPath(const char *path)
{
    gstate = PyGILState_Ensure();

    strncpy(pyci_dbpath, path, MAX_PATH);
    pyci_dbpath[MAX_PATH] = 0;

    pyci_freeDB();

    if (pyci_dbstat)
        pyci_dbstatFree();

    PyGILState_Release(gstate);
}

static int pyci_loadDB(void)
{
    int ret = 0;
    struct cl_settings *settings = NULL;

    assert(pyci_engine);

    gstate = PyGILState_Ensure();

    vmain = vdaily = sigs = 0;

    settings = cl_engine_settings_copy(pyci_engine);

    if(!settings)
        fprintf(stderr, "Can't make a copy of the current engine settings\n");

    pyci_freeDB();

    pyc_DEBUG(loadDB(internal), "Loading db from %s\n", pyci_dbpath);

    if (!(pyci_engine = cl_engine_new()))
    {
        PyErr_SetString(PycError, "loadDB(internal): Can't initialize antivirus engine");
        goto cleanup;
    }

    if (settings)
    {
        if ((ret = cl_engine_settings_apply(pyci_engine, settings)) != CL_SUCCESS)
        {
            fprintf(stderr, "Can't apply previous engine settings: %s\n", cl_strerror(ret));
            fprintf(stderr, "Using default engine settings\n");
        }
    }

    if ((ret = cl_load(pyci_dbpath, pyci_engine, &sigs, CL_DB_STDOPT)))
    {
        PyErr_PycFromClamav(loadDB(internal)::cl_load, ret);
        pyci_freeDB();
        goto cleanup;
    }

    if ((ret = cl_engine_compile(pyci_engine)))
    {
        PyErr_PycFromClamav(loadDB(internal)::cl_engine_compile, ret);
        pyci_freeDB();
        goto cleanup;
    }


    ret = pyci_dbstatNew();
    pyci_lastcheck = time(NULL);

 cleanup:
    if (settings)
        cl_engine_settings_free(settings);

    PyGILState_Release(gstate);
    if (!ret) pyci_getVersions(&vmain, &vdaily);
    return ret;
}

static void pyci_dbstatFree(void)
{
    assert(pyci_dbstat);
    cl_statfree(pyci_dbstat);
    PyMem_Free(pyci_dbstat);
    pyci_dbstat = NULL;
}

static int pyci_dbstatNew(void)
{
    int ret;
    if (pyci_dbstat) pyci_dbstatFree();

    if (!(pyci_dbstat = PyMem_Malloc(sizeof(struct cl_stat))))
    {
        pyc_DEBUG(pyci_dbstatNew, "Out of memory\n");
        return CL_EMEM;
    }

    pyc_DEBUG(pyci_dbstatNew, "Calling cl_statinidir() on %s\n", pyci_dbpath);
    if ((ret = cl_statinidir(pyci_dbpath, pyci_dbstat)))
    {
        PyErr_PycFromClamav(dbstatNew::cl_statinidir, ret);
        PyMem_Free(pyci_dbstat);
        return ret;
    }
    return CL_SUCCESS;
}

static int pyci_checkAndLoadDB(int force)
{
    int ret;
    assert(pyci_engine);

    if (!pyci_isCompiled)
        return pyci_loadDB();

    if (!force)
    {
        if (pyci_checktimer == PYC_SELFCHECK_NEVER) return CL_SUCCESS;

        if ((pyci_checktimer > 0) || !pyci_lastcheck)
        {
            time_t now = time(NULL);
            if ((now - pyci_lastcheck) < pyci_checktimer)
                return CL_SUCCESS;
        }
    }

    pyc_DEBUG(checkAndLoadDB, "SelfCheck\n");

    if (!pyci_dbstat && (ret = pyci_dbstatNew()))
        return ret;

    pyci_lastcheck = time(NULL);

    switch ((ret = cl_statchkdir(pyci_dbstat)))
    {
        case 1: /* needs to be reloaded */
            pyc_DEBUG(pyci_checkAndLoadDB, "virus db needs to be reloaded\n");
            break;
        case CL_SUCCESS:
            pyc_DEBUG(pyci_checkAndLoadDB, "virus db is up to date\n");
            return CL_SUCCESS;
        default:
            PyErr_PycFromClamav(checkAndLoadDB::cl_statchkdir, ret);
            return ret;
    }

    return pyci_loadDB();
}

static void pyci_cleanup(void)
{
    if (pyci_dbstat) pyci_dbstatFree();
    if (pyci_engine) cl_engine_free(pyci_engine);
}

/* Public */
static PyObject *pyc_checkAndLoadDB(PyObject *self, PyObject *args)
{
    int ret;
    if ((ret = pyci_checkAndLoadDB(1)))
    {
        PyErr_PycFromClamav(pyc_loadDB, ret);
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *pyc_getVersions(PyObject *self, PyObject *args)
{
    const char *version;
    assert(pyci_engine);

    if (!pyci_isCompiled)
    {
        PyErr_SetString(PycError, "getVersions: No database loaded");
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
        PyErr_SetString(PycError, "setDBPath: Database path must be a String");
        return NULL;
    }

    if (lstat(path, &dp) < 0)
    {
        PyErr_PycFromErrno(pyc_setDBPath);
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
        PyErr_SetString(PycError, "loadDB: Invalid arguments");
        return NULL;
    }

    if (result)
    {
        if (PyString_Check(result))
            pyci_setDBPath(PyString_AsString(result));
        else
        {
            PyErr_SetString(PyExc_TypeError, "loadDB: Database path must be a String");
            return NULL;
        }
    }

    if ((ret = pyci_checkAndLoadDB(1)))
    {
        PyErr_PycFromClamav(loadDB, ret);
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *pyc_setDBTimer(PyObject *self, PyObject *args)
{
    int value = 0;
    if (!PyArg_ParseTuple(args, "i", &value))
    {
        PyErr_SetString(PycError, "setDBTimer: Invalid arguments");
        return NULL;
    }

    pyci_checktimer = value;
    Py_RETURN_NONE;
}

static PyObject *pyc_isLoaded(PyObject *self, PyObject *args)
{
    if (pyci_engine && pyci_isCompiled)
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

/* Warning passing fd on windows works only if the crt used by python is
   the same used to compile libclamav */
static PyObject *pyc_scanDesc(PyObject *self, PyObject *args)
{
    unsigned int ret;
    unsigned long scanned = 0;
    const char *virname = NULL;
    int fd = -1;

    assert(pyci_engine);

    if (!PyArg_ParseTuple(args, "i", &fd) || (fd < 0))
    {
        PyErr_SetString(PycError, "scanDesc: Invalid arguments");
        return NULL;
    }

    if ((ret = pyci_checkAndLoadDB(0)))
    {
        PyErr_PycFromClamav(scanDesc, ret);
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS;
    ret = cl_scandesc(fd, &virname, &scanned, pyci_engine, pyci_options);
    Py_END_ALLOW_THREADS;

    switch (ret)
    {
        case CL_CLEAN: return Py_BuildValue("(O,s)", Py_False, "CLEAN");
        case CL_VIRUS: return Py_BuildValue("(O,s)", Py_True,  virname);
    }

    PyErr_PycFromClamav(ScanDesc, ret);
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
        PyErr_SetString(PyExc_TypeError, "scanFile: A string is needed for the filename");
        return NULL;
    }

#ifdef _WIN32
    if (!(filename = cw_normalizepath(filename)))
        PyErr_SetString(PycError, "scanFile: Path Normalization failed");
#endif

    if (lstat(filename, &info) < 0)
    {
        PyErr_PycFromErrno(scanFile);
        goto sf_cleanup;
    }

    if (!(S_ISREG(info.st_mode) || S_ISLNK(info.st_mode)))
    {
        PyErr_SetString(PycError, "scanFile: Not a regular file");
        goto sf_cleanup;
    }

    if ((fd = open(filename, O_RDONLY | O_BINARY)) < 0)
    {
        PyErr_PycFromErrno(scanFile);
        goto sf_cleanup;
    }

    result = pyc_scanDesc(self, Py_BuildValue("(i)", fd));
    close(fd);

 sf_cleanup:
#ifdef _WIN32
    if (filename) free(filename);
#endif
    return result;
}

static PyObject *pyc_setDebug(PyObject *self, PyObject *args)
{
    cl_debug();
    Py_RETURN_NONE;
}

static PyObject *pyc_setEngineOption(PyObject *self, PyObject *args)
{
    char *option;
    PyObject *value;
    int ret, i;

    assert(pyci_engine);

    if (!PyArg_ParseTuple(args, "sO", &option, &value))
    {
        PyErr_SetString(PyExc_TypeError, "setEngineOption: Invalid arguments");
        return NULL;
    }

    for (i = 0; engine_options[i].name; i++)
    {
        if (strcmp(option, engine_options[i].name)) continue;

        if (engine_options[i].readonly)
        {
            PyErr_SetString(PyExc_TypeError, "setEngineOption: The option is read-only");
            return NULL;
        }

        switch (engine_options[i].type)
        {
            case OPT_NUM:
            {
                uint32_t val = PyInt_AsLong(value);
                gstate = PyGILState_Ensure();
                ret = cl_engine_set_num(pyci_engine, engine_options[i].id, val);
                PyGILState_Release(gstate);
                if (ret)
                {
                    PyErr_PycFromClamav(setEngineOption::cl_engine_set_num, ret);
                    return NULL;
                }
                Py_RETURN_NONE;
                break;
            }
            case OPT_STR:
            {
                char *val = PyString_AsString(value);
                gstate = PyGILState_Ensure();
                ret = cl_engine_set_str(pyci_engine, engine_options[i].id, val);
                PyGILState_Release(gstate);
                if (ret)
                {
                    PyErr_PycFromClamav(setEngineOption::cl_engine_set_str, ret);
                    return NULL;
                }
                Py_RETURN_NONE;
                break;
            }
            default:
                PyErr_SetString(PyExc_TypeError, "setEngineOption: Internal Error");
        }
    }
    PyErr_SetString(PyExc_TypeError, "setEngineOption: Invalid option");
    return NULL;
}

static PyObject *pyc_getEngineOption(PyObject *self, PyObject *args)
{
    char *option;
    int ret, i;

    if (!PyArg_ParseTuple(args, "s", &option))
    {
        PyErr_SetString(PyExc_TypeError, "setEngineOption: Invalid arguments");
        return NULL;
    }

    for (i = 0; engine_options[i].name; i++)
    {
        if (strcmp(option, engine_options[i].name)) continue;
        switch (engine_options[i].type)
        {
            case OPT_NUM:
            {
                int64_t result = cl_engine_get_num(pyci_engine, engine_options[i].id, &ret);
                if (result == -1)
                {
                    PyErr_PycFromClamav(getEngineOption::cl_engine_get_num, ret);
                    return NULL;
                }
                return PyLong_FromLongLong(result);
                break;
            }
            case OPT_STR:
            {
                const char *result = cl_engine_get_str(pyci_engine, engine_options[i].id, &ret);
                if (!result)
                {
                    PyErr_PycFromClamav(getEngineOption::cl_engine_get_str, ret);
                    return NULL;
                }
                return PyString_FromString(result);
                break;
            }
            default:
                PyErr_SetString(PyExc_TypeError, "getEngineOption: Internal Error");
        }
    }
    PyErr_SetString(PyExc_TypeError, "getEngineOption: Invalid option");
    return NULL;
}

static PyObject *pyc_setScanOption(PyObject *self, PyObject *args)
{
    char *option = NULL;
    PyObject *value = NULL;
    int i;

    if (!PyArg_ParseTuple(args, "sO", &option, &value))
    {
        PyErr_SetString(PyExc_TypeError, "pyc_setScanOption: Invalid arguments");
        return NULL;
    }

    if (!PyBool_Check(value))
    {
        PyErr_SetString(PyExc_TypeError, "pyc_setScanOption: A Boolean is needed as option value");
        return NULL;
    }


    for (i = 0; scan_options[i].name; i++)
    {
        if (strcmp(option, scan_options[i].name)) continue;

        gstate = PyGILState_Ensure();

        if (PyObject_IsTrue(value))
            pyci_options |= scan_options[i].id;
        else
            pyci_options &= ~scan_options[i].id;
        break;

        PyGILState_Release(gstate);
        Py_RETURN_NONE;
    }

    PyErr_SetString(PyExc_TypeError, "setEngineOption: Invalid option");
    return NULL;
}

static PyObject *pyc_getScanOptions(PyObject *self, PyObject *args)
{
    int i;
    PyObject *list = PyList_New(0);

    if (!list)
    {
        PyErr_SetString(PyExc_RuntimeError, "pyc_getScanOptions: Cannot allocate memory for the List");
        return NULL;
    }

    for (i = 0; scan_options[i].name; i++)
        if (pyci_options & scan_options[i].id)
            PyList_Append(list, PyString_FromString(scan_options[i].name));

    return list;
}

#ifdef _WIN32
static PyObject *pyc_fsRedirect(PyObject *self, PyObject *args)
{
    PyObject *value = NULL;

    if (!PyArg_ParseTuple(args, "O", &value))
    {
        PyErr_SetString(PyExc_TypeError, "pyc_fsRedirect: Invalid arguments");
        return NULL;
    }

    if (!PyBool_Check(value))
    {
        PyErr_SetString(PyExc_TypeError, "pyc_fsRedirect: A Boolean is needed to set fs redirection");
        return NULL;
    }

    if (cw_fsredirection((PyObject_IsTrue(value) ? TRUE : FALSE)))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

static PyObject *pyc_isWow64(PyObject *self, PyObject *args)
{
    if (cw_iswow64())
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}
#endif

/* Methods Table */
static PyMethodDef pycMethods[] =
{
    { "getVersions",        pyc_getVersions,        METH_VARARGS, "Get clamav and database versions"        },
    { "checkAndLoadDB",     pyc_checkAndLoadDB,     METH_VARARGS, "Reload virus database if changed"        },

    { "setDBPath",          pyc_setDBPath,          METH_VARARGS, "Set path for virus database"             },
    { "getDBPath",          pyc_getDBPath,          METH_VARARGS, "Get path for virus database"             },

    { "loadDB",             pyc_loadDB,             METH_VARARGS|METH_KEYWORDS, "Load a virus database"     },
    { "setDBTimer",         pyc_setDBTimer,         METH_VARARGS, "Set database check time"                 },

    { "isLoaded",           pyc_isLoaded,           METH_VARARGS, "Check if db is loaded or not"            },

    { "scanDesc",           pyc_scanDesc,           METH_VARARGS, "Scan a file descriptor"                  },
    { "scanFile",           pyc_scanFile,           METH_VARARGS, "Scan a file"                             },

    { "setDebug",           pyc_setDebug,           METH_VARARGS, "Enable libclamav debug messages"         },

    { "setEngineOption",    pyc_setEngineOption,    METH_VARARGS, "Set an engine option"                    },
    { "getEngineOption",    pyc_getEngineOption,    METH_VARARGS, "Get an engine option"                    },

    { "setScanOption",      pyc_setScanOption,      METH_VARARGS, "Set a scan option"                       },
    { "getScanOptions",     pyc_getScanOptions,     METH_VARARGS, "Get the list of scan options"            },

#ifdef _WIN32
    { "fsRedirect",     pyc_fsRedirect,     METH_VARARGS, "Enable / Disable Win64 fs redirection"   },
    { "isWow64",        pyc_isWow64,        METH_VARARGS, "Check if we are running on wow"          },
#endif
    { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC
initpyc(void)
{
    int ret;
    PyObject *m = Py_InitModule("pyc", pycMethods);

    PycError = PyErr_NewException("pyc.PycError", NULL, NULL);
    PyModule_AddObject(m, "PycError", PycError);

    PyModule_AddStringConstant(m, "__version__", PYC_VERSION);
    PyModule_AddIntConstant(m, "SELFCHECK_NEVER", PYC_SELFCHECK_NEVER);
    PyModule_AddIntConstant(m, "SELFCHECK_ALWAYS", PYC_SELFCHECK_ALWAYS);

    /* argh no way to bail out from here? */
    if ((ret = cl_init(CL_INIT_DEFAULT)))
        fprintf(stderr, "Can't initialize libclamav: %s\n", cl_strerror(ret));

    if (!(pyci_engine = cl_engine_new()))
        fprintf(stderr, "Can't initialize antivirus engine");

    strncat(pyci_dbpath, cl_retdbdir(), MAX_PATH);
    pyci_dbpath[MAX_PATH] = 0;

    Py_AtExit(pyci_cleanup);
}
