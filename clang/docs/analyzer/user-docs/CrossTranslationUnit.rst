=====================================
Cross Translation Unit (CTU) Analysis
=====================================

Normally, static analysis works in the boundary of one translation unit (TU).
However, with additional steps and configuration we can enable the analysis to inline the definition of a function from another TU.

Manual CTU Analysis
-------------------

Let's consider these source files in our minimal example:

.. code-block:: cpp

  // main.cpp
  int foo();

  int main() {
    return 3 / foo();
  }

.. code-block:: cpp

  // foo.cpp
  int foo() {
    return 0;
  }

And a compilation database:

.. code-block:: bash

  [
    {
      "directory": "/path/to/your/project",
      "command": "clang++ -c foo.cpp -o foo.o",
      "file": "foo.cpp"
    },
    {
      "directory": "/path/to/your/project",
      "command": "clang++ -c main.cpp -o main.o",
      "file": "main.cpp"
    }
  ]

We'd like to analyze `main.cpp` and discover the division by zero bug.
In order to be able to inline the definition of `foo` from `foo.cpp` first we have to generate the `AST` (or `PCH`) file of `foo.cpp`:

.. code-block:: bash

  $ pwd $ /path/to/your/project
  $ clang++ -emit-ast -o foo.cpp.ast foo.cpp
  $ # Check that the .ast file is generated:
  $ ls
  compile_commands.json  foo.cpp.ast  foo.cpp  main.cpp
  $

The next step is to create a CTU index file which holds the `USR` name and location of external definitions in the source files:

.. code-block:: bash

  $ clang-extdef-mapping -p . foo.cpp
  c:@F@foo# /path/to/your/project/foo.cpp
  $ clang-extdef-mapping -p . foo.cpp > externalDefMap.txt

We have to modify `externalDefMap.txt` to contain the name of the `.ast` files instead of the source files:

.. code-block:: bash

  $ sed -i -e "s/.cpp/.cpp.ast/g" externalDefMap.txt

We still have to further modify the `externalDefMap.txt` file to contain relative paths:

.. code-block:: bash

  $ sed -i -e "s|$(pwd)/||g" externalDefMap.txt

Now everything is available for the CTU analysis.
We have to feed Clang with CTU specific extra arguments:

.. code-block:: bash

  $ pwd
  /path/to/your/project
  $ clang++ --analyze -Xclang -analyzer-config -Xclang experimental-enable-naive-ctu-analysis=true -Xclang -analyzer-config -Xclang ctu-dir=. -Xclang -analyzer-output=plist-multi-file main.cpp
  main.cpp:5:12: warning: Division by zero
    return 3 / foo();
           ~~^~~~~~~
  1 warning generated.
  $ # The plist file with the result is generated.
  $ ls
  compile_commands.json  externalDefMap.txt  foo.ast  foo.cpp  foo.cpp.ast  main.cpp  main.plist
  $

This manual procedure is boring and error-prone, so sooner or later we'd like to have a script which automates this for us.

Automated CTU Analysis with CodeChecker
---------------------------------------
The `CodeChecker <https://github.com/Ericsson/codechecker>`_ project fully supports automated CTU analysis with Clang.
Once we have set up the `PATH` environment variable and we activated the python `venv` then it is all it takes:

#.. code-block:: bash

Automated CTU Analysis with scan-build (don't do it)
----------------------------------------------------
We actively develop CTU with CodeChecker as a "runner" script, `scan-build` is not actively developed for CTU.
`scan-build` has different errors and issues, expect it to work with the very basic projects only.
