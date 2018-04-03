|language| |license|

=========
goudpscan
=========

Description
~~~~~~~~~~~

Fastest UDP port scanner you've ever seen.

Build
~~~~~

``go build -o bin/goudpscan``

Installation
~~~~~~~~~~~~

``./install.sh``

How to use
~~~~~~~~~~

Run ``sudo goudpscan -f -t 1 -c 975 -p 19-22 -s 127.0.0-32.0/24 127.1.0.1``

Also checkout list of `flags`_ and `arguments`_

flags
^^^^^
* ``-f, --fast`` - Fast scan mode. Only "Open" or "Unknown" statuses.
* ``-t, --timeout`` - Timeout. How long to wait for response.
* ``-r, --recheck`` - Recheck. How many times to check every port.
* ``-c, --maxConcurrency`` - Maximum concurrency. How many to scan concurrently every timeout.
* ``-s, --sort`` - Sort results.
* ``-p, --ports`` - Ports to scan.

arguments
^^^^^^^^^
* ``<hosts>`` - Hosts to scan.

.. |language| image:: https://img.shields.io/badge/language-go-green.svg
.. |license| image:: https://img.shields.io/badge/license-Apache%202-blue.svg
