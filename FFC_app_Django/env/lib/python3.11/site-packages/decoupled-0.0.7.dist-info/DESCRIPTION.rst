# decoupled

## Motivation
Imagine...
* You're developing a python extension OR
* You're writing some C or C++ code, but decided to add some python bindings
because you're more familiar with python unit testing libraries

Now this C/C++ code can fail in ways which Python code cannot.
It can cause a segfault and take your whole Python process down.
That means, that your testing library doesn't get to display it's results - 
you don't get told which tests fail.

## The solution
decoupled runs your code in a separate process. If it crashes, this doesn't
take down the parent process. Instead, a ChildCrashedError is raised
in your parent process.


