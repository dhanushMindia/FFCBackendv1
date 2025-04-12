# These are tests. Do we really need docstrings?
# pylint: disable=missing-docstring

import time
import multiprocessing
import os
from inspect import getfullargspec
from traceback import extract_tb

import pytest  # type: ignore

from decoupled import decoupled, ChildTimeoutError, ChildCrashedError


def test_func_is_run_with_correct_parameters():
    @decoupled()
    def func(positional_param, named_param):
        assert positional_param == 42
        assert named_param == 'foo'

    func(42, named_param='foo')


def test_normal_returns_work():
    @decoupled()
    def func():
        return 42

    assert func() == 42


def test_exceptions_are_passed_through():
    @decoupled()
    def func():
        raise ValueError()

    with pytest.raises(ValueError):
        func()


def test_exceptions_are_passed_through_unchanged():
    def func():
        raise ValueError('foo')

    try:
        func()
    except ValueError as exc:
        unmodified_exception = exc

    func = decoupled(func)
    try:
        func()
    except ValueError as exc:
        decorated_exception = exc

    assert unmodified_exception.args == decorated_exception.args
    assert unmodified_exception.__cause__ == decorated_exception.__cause__
    assert unmodified_exception.__context__ == decorated_exception.__context__
    assert (unmodified_exception.__suppress_context__ ==
            decorated_exception.__suppress_context__)


def test_exceptions_have_a_sensible_traceback():
    # Comparing tracebacks is difficult for 2 reasons:
    #
    # 1) when we are using a decorator, we are adding the decorator
    #    to the stack.
    #
    # 2) tracebacks aren't pickleable.
    #
    # But we want our exceptions to have at least sensible tracebacks,
    # so that e.g. pytest can show us where our bugs are (if we @decouple our
    # test cases).
    #
    # To workaround 2), we use tblib.
    #
    # Because of 1), we still cannot simply compare the complete tracebacks -
    # but we can compare the top-of-the-stack entry. Which is the most
    # important one.

    def run_func_twice():
        # run func twice - once without @decoupled, once with @decoupled.
        # This is written this way, so that the "expected" exception and the
        # "actual" exception are raised from the same line of code
        def func_that_raises():
            raise ValueError('foo')

        for _run in (1, 2):
            try:
                func_that_raises()
            except ValueError as exc:
                yield exc
            func_that_raises = decoupled(func_that_raises)

    (unmodified_exception, decorated_exception) = run_func_twice()

    assert (extract_tb(unmodified_exception.__traceback__)[-1] ==
            extract_tb(decorated_exception.__traceback__)[-1])


def test_timeout_causes_an_exception():
    @decoupled(timeout=.1)
    def func():
        time.sleep(2)

    with pytest.raises(ChildTimeoutError):
        func()


def test_children_are_gone():
    @decoupled(timeout=.1)
    def func():
        time.sleep(2)

    try:
        func()
    except ChildTimeoutError:
        pass

    time.sleep(.1)

    assert multiprocessing.active_children() == []


def test_crashing_causes_an_exception():
    @decoupled()
    def func():
        os._exit(1)  # pylint: disable=protected-access

    with pytest.raises(ChildCrashedError):
        func()


def test_decorated_functions_keep_signatures():
    @decoupled()
    def func1(positional, named=42):  # pylint: disable=unused-argument
        pass

    def func2(positional, named=42):  # pylint: disable=unused-argument
        pass

    assert getfullargspec(func1) == getfullargspec(func2)
