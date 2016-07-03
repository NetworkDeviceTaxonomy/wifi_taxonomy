#!/usr/bin/env python
#
# WvTest:
#   Copyright (C)2007-2012 Versabanq Innovations Inc. and contributors.
#       Licensed under the GNU Library General Public License, version 2.
#       See the included file named LICENSE for license information.
#       You can get wvtest from: http://github.com/apenwarr/wvtest
#
import atexit
import inspect
import os
import re
import sys
import traceback

# NOTE
# Why do we do we need the "!= main" check?  Because if you run
# wvtest.py as a main program and it imports your test files, then
# those test files will try to import the wvtest module recursively.
# That actually *works* fine, because we don't run this main program
# when we're imported as a module.  But you end up with two separate
# wvtest modules, the one that gets imported, and the one that's the
# main program.  Each of them would have duplicated global variables
# (most importantly, wvtest._registered), and so screwy things could
# happen.  Thus, we make the main program module *totally* different
# from the imported module.  Then we import wvtest (the module) into
# wvtest (the main program) here and make sure to refer to the right
# versions of global variables.
#
# All this is done just so that wvtest.py can be a single file that's
# easy to import into your own applications.
if __name__ != '__main__':   # we're imported as a module
    _registered = []
    _tests = 0
    _fails = 0

    def wvtest(func, innerfunc=None):
        """ Use this decorator (@wvtest) in front of any function you want to
            run as part of the unit test suite.  Then run:
                python wvtest.py path/to/yourtest.py [other test.py files...]
            to run all the @wvtest functions in the given file(s).
        """
        _registered.append((func, innerfunc or func))
        return func


    def _result(msg, tb, code):
        global _tests, _fails
        _tests += 1
        if code != 'ok':
            _fails += 1
        (filename, line, func, text) = tb
        filename = os.path.basename(filename)
        msg = re.sub(r'\s+', ' ', str(msg))
        sys.stderr.flush()
        print '! %-70s %s' % ('%s:%-4d %s' % (filename, line, msg),
                              code)
        sys.stdout.flush()


    def _check(cond, msg, xdepth):
        tb = traceback.extract_stack()[-3 - xdepth]
        if cond:
            _result(msg, tb, 'ok')
        else:
            _result(msg, tb, 'FAILED')
        return cond


    def _code(xdepth):
        (filename, line, func, text) = traceback.extract_stack()[-3 - xdepth]
        text = re.sub(r'^[\w\.]+\((.*)\)(\s*#.*)?$', r'\1', str(text));
        return text


    def WVPASS(cond = True, xdepth = 0):
        ''' Counts a test failure unless cond is true. '''
        return _check(cond, _code(xdepth), xdepth)

    def WVFAIL(cond = True, xdepth = 0):
        ''' Counts a test failure  unless cond is false. '''
        return _check(not cond, 'NOT(%s)' % _code(xdepth), xdepth)

    def WVPASSIS(a, b, xdepth = 0):
        ''' Counts a test failure unless a is b. '''
        return _check(a is b, '%s is %s' % (repr(a), repr(b)), xdepth)

    def WVPASSISNOT(a, b, xdepth = 0):
        ''' Counts a test failure unless a is not b. '''
        return _check(a is not b, '%s is not %s' % (repr(a), repr(b)), xdepth)

    def WVPASSEQ(a, b, xdepth = 0):
        ''' Counts a test failure unless a == b. '''
        return _check(a == b, '%s == %s' % (repr(a), repr(b)), xdepth)

    def WVPASSNE(a, b, xdepth = 0):
        ''' Counts a test failure unless a != b. '''
        return _check(a != b, '%s != %s' % (repr(a), repr(b)), xdepth)

    def WVPASSLT(a, b, xdepth = 0):
        ''' Counts a test failure unless a < b. '''
        return _check(a < b, '%s < %s' % (repr(a), repr(b)), xdepth)

    def WVPASSLE(a, b, xdepth = 0):
        ''' Counts a test failure unless a <= b. '''
        return _check(a <= b, '%s <= %s' % (repr(a), repr(b)), xdepth)

    def WVPASSGT(a, b, xdepth = 0):
        ''' Counts a test failure unless a > b. '''
        return _check(a > b, '%s > %s' % (repr(a), repr(b)), xdepth)

    def WVPASSGE(a, b, xdepth = 0):
        ''' Counts a test failure unless a >= b. '''
        return _check(a >= b, '%s >= %s' % (repr(a), repr(b)), xdepth)

    def WVPASSNEAR(a, b, places = 7, delta = None, xdepth = 0):
        ''' Counts a test failure unless a ~= b. '''
        if delta:
            return _check(abs(a - b) <= abs(delta),
                          '%s ~= %s' % (repr(a), repr(b)), xdepth)
        else:
            return _check(round(a, places) == round(b, places),
                          '%s ~= %s' % (repr(a), repr(b)), xdepth)

    def WVPASSFAR(a, b, places = 7, delta = None, xdepth = 0):
        ''' Counts a test failure unless a ~!= b. '''
        if delta:
            return _check(abs(a - b) > abs(delta),
                          '%s ~= %s' % (repr(a), repr(b)), xdepth)
        else:
            return _check(round(a, places) != round(b, places),
                          '%s ~= %s' % (repr(a), repr(b)), xdepth)

    def _except_report(cond, code, xdepth):
        return _check(cond, 'EXCEPT(%s)' % code, xdepth + 1)

    class _ExceptWrapper(object):
        def __init__(self, etype, xdepth):
            self.etype = etype
            self.xdepth = xdepth
            self.code = None

        def __enter__(self):
          self.code = _code(self.xdepth)

        def __exit__(self, etype, value, traceback):
            if etype == self.etype:
                _except_report(True, self.code, self.xdepth)
                return 1  # success, got the expected exception
            elif etype is None:
                _except_report(False, self.code, self.xdepth)
                return 0
            else:
                _except_report(False, self.code, self.xdepth)

    def _WVEXCEPT(etype, xdepth, func, *args, **kwargs):
        if func:
            code = _code(xdepth + 1)
            try:
                func(*args, **kwargs)
            except etype, e:
                return _except_report(True, code, xdepth + 1)
            except:
                _except_report(False, code, xdepth + 1)
                raise
            else:
                return _except_report(False, code, xdepth + 1)
        else:
            return _ExceptWrapper(etype, xdepth)

    def WVEXCEPT(etype, func=None, *args, **kwargs):
        ''' Counts a test failure unless func throws an 'etype' exception.
            You have to spell out the function name and arguments, rather than
            calling the function yourself, so that WVEXCEPT can run before
            your test code throws an exception.
        '''
        return _WVEXCEPT(etype, 0, func, *args, **kwargs)


    def _check_unfinished():
        if _registered:
            for func, innerfunc in _registered:
                print 'WARNING: not run: %r' % (innerfunc,)
            WVFAIL('wvtest_main() not called')
        if _fails:
            sys.exit(1)

    atexit.register(_check_unfinished)


def _run_in_chdir(path, func, *args, **kwargs):
    oldwd = os.getcwd()
    oldpath = sys.path
    try:
        if path: os.chdir(path)
        sys.path += [path, os.path.split(path)[0]]
        return func(*args, **kwargs)
    finally:
        os.chdir(oldwd)
        sys.path = oldpath


def _runtest(fname, f, innerfunc):
    import wvtest as _wvtestmod
    mod = inspect.getmodule(innerfunc)
    relpath = os.path.relpath(mod.__file__, os.getcwd()).replace('.pyc', '.py')
    print
    print 'Testing "%s" in %s:' % (fname, relpath)
    sys.stdout.flush()
    try:
        _run_in_chdir(os.path.split(mod.__file__)[0], f)
    except Exception, e:
        print
        print traceback.format_exc()
        tb = sys.exc_info()[2]
        _wvtestmod._result(repr(e), traceback.extract_tb(tb)[-1], 'EXCEPTION')


def _run_registered_tests():
    import wvtest as _wvtestmod
    while _wvtestmod._registered:
        func, innerfunc = _wvtestmod._registered.pop(0)
        _runtest(innerfunc.func_name, func, innerfunc)
        print


def wvtest_main(extra_testfiles=[]):
    import wvtest as _wvtestmod
    _run_registered_tests()
    for modname in extra_testfiles:
        if not os.path.exists(modname):
            print 'Skipping: %s' % modname
            continue
        if modname.endswith('.py'):
            modname = modname[:-3]
        print 'Importing: %s' % modname
        path, mod = os.path.split(os.path.abspath(modname))
        nicename = modname.replace(os.path.sep, '.')
        while nicename.startswith('.'):
            nicename = modname[1:]
        _run_in_chdir(path, __import__, nicename, None, None, [])
        _run_registered_tests()
    print
    print 'WvTest: %d tests, %d failures.' % (_wvtestmod._tests,
                                              _wvtestmod._fails)


if __name__ == '__main__':
    import wvtest as _wvtestmod
    sys.modules['wvtest'] = _wvtestmod
    sys.modules['wvtest.wvtest'] = _wvtestmod
    wvtest_main(sys.argv[1:])
