Electrum-CIVX - Lightweight CivX client
=====================================

::

  Licence: MIT Licence
  Original Author: Thomas Voegtlin
  Port Maintainer: ExF Developers, Fluid Chains, turcol
  Language: Python
  Homepage: https://civxeconomy.com/


.. image:: https://travis-ci.org/exofoundation/electrum-civx.svg?branch=master
    :target: https://travis-ci.org/exofoundation/electrum-civx
    :alt: Build Status
.. image:: https://coveralls.io/repos/github/spesmilo/electrum/badge.svg?branch=master
    :target: https://coveralls.io/github/spesmilo/electrum?branch=master
    :alt: Test coverage statistics
.. image:: https://d322cqt584bo4o.cloudfront.net/electrum/localized.svg
    :target: https://crowdin.com/project/electrum
    :alt: Help translate Electrum online





Getting started
===============

Electrum-CIVX is a pure python application. If you want to use the
Qt interface, install the Qt dependencies::

    sudo apt-get install python3-pyqt5

If you downloaded the official package (tar.gz), you can run
Electrum-CIVX from its root directory, without installing it on your
system; all the python dependencies are included in the 'packages'
directory. To run Electrum-CIVX from its root directory, just do::

    ./run_electrum

You can also install Electrum-CIVX on your system, by running this command::

    sudo apt-get install python3-setuptools
    pip3 install .[fast]

This will download and install the Python dependencies used by
Electrum-CIVX, instead of using the 'packages' directory.
The 'fast' extra contains some optional dependencies that we think
are often useful but they are not strictly needed.

If you cloned the git repository, you need to compile extra files
before you can run Electrum-CIVX. Read the next section, "Development
Version".



Development version
===================

Check out the code from GitHub::

    git clone git://github.com/exofoundation/electrum-civx.git
    cd electrum-civx

Run install (this should install dependencies)::

    pip3 install .[fast]

Render the SVG icons to PNGs (optional)::

    for i in lock unlock confirmed status_lagging status_disconnected status_connected_proxy status_connected status_waiting preferences; do convert -background none icons/$i.svg icons/$i.png; done

Compile the icons file for Qt::

    sudo apt-get install pyqt5-dev-tools
    pyrcc5 icons.qrc -o electrum/gui/qt/icons_rc.py

Compile the protobuf description file::

    sudo apt-get install protobuf-compiler
    protoc --proto_path=electrum --python_out=electrum electrum/paymentrequest.proto

Create translations (optional)::

    sudo apt-get install python-requests gettext
    ./contrib/make_locale




Creating Binaries
=================


To create binaries, create the 'packages' directory::

    ./contrib/make_packages

This directory contains the python dependencies used by Electrum-CIVX.

Mac OS X / macOS
--------

See `contrib/build-osx/`.

Windows
-------

See `contrib/build-wine/`.


Android
-------

See `electrum/gui/kivy/Readme.md` file.
