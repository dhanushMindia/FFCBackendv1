''' decoupled: run a function in a different process '''

import multiprocessing
import queue
from typing import (
        Any,
        Callable,
        Literal,
        Mapping,
        Optional,
        Sequence,
        TYPE_CHECKING,
        Tuple,
        TypedDict,
        Union,
)

from decorator import decorator
from tblib import Traceback  # type: ignore


class ResultSuccess(TypedDict):
    ''' The function call was successful '''
    return_type: Literal['success']
    return_value: Any


class ResultError(TypedDict):
    ''' The function call raised an Exception '''
    return_type: Literal['error']
    err: Exception
    traceback: Any  # because tblib isn't annotated


Result = Union[ResultSuccess, ResultError]
if TYPE_CHECKING:
    ResultQueue = queue.Queue[Result]  # pylint: disable=unsubscriptable-object
else:
    ResultQueue = queue.Queue


@decorator
def decoupled(  # pylint: disable=keyword-arg-before-vararg
        # This is the order decorator needs
        func: Callable,
        timeout: Optional[float] = None,
        *args,
        **kwargs,
) -> Any:
    ''' run a function in a different process '''
    result_queue, process = run_subprocess(func, args, kwargs, timeout)

    try:
        return determine_result(result_queue, process)
    finally:
        process.terminate()


def run_subprocess(
        func: Callable,
        args: Sequence,
        kwargs: Mapping,
        timeout: Optional[float],
) -> Tuple[ResultQueue, Any]:
    '''
    run func in a separate process and wait for it to terminate
    (one way or another)
    returns a tuple (result_queue, process), where...
    - result_queue is used to communicate return value / exceptions thrown
    - process is the actual process object
    '''
    result_queue: multiprocessing.Queue = multiprocessing.Queue()

    process = multiprocessing.Process(
        target=proc,
        args=(result_queue, func, args, kwargs),
    )
    process.start()
    process.join(timeout=timeout)

    return result_queue, process


def proc(
        result_queue: ResultQueue,
        func: Callable,
        args: Sequence,
        kwargs: Mapping,
) -> None:
    ''' This is what's run in the other process. '''
    try:
        result: ResultSuccess = {
            'return_type': 'success',
            'return_value': func(*args, **kwargs),
        }
        result_queue.put(result)
    except Exception as err:  # pylint: disable=broad-except
        result_error: ResultError = {
            'return_type': 'error',
            'err': err,
            'traceback': Traceback(err.__traceback__).to_dict(),
        }
        result_queue.put(result_error)


def determine_result(
        result_queue: ResultQueue,
        process: multiprocessing.Process,
):
    '''
    Find out what happened in the subprocess
    and return/raise accordingly
    '''
    if process.exitcode is None:
        raise ChildTimeoutError

    try:
        retval = result_queue.get_nowait()
        if retval['return_type'] == 'success':
            return retval['return_value']
        raise retval['err'].with_traceback(
            Traceback.from_dict(retval['traceback']).as_traceback())
    except queue.Empty:
        raise ChildCrashedError
    raise ValueError('This should not be reachable - but pylint thinks it is.')


class ChildTimeoutError(Exception):
    ''' thrown when the child process takes too long '''


class ChildCrashedError(Exception):
    ''' thrown when the child process crashes '''
