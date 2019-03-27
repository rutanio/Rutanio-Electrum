#!/usr/bin/env python3

# python setup.py sdist --format=zip,gztar

import os
import sys
import platform
import imp
import argparse
import subprocess

from setuptools import setup, find_packages
from setuptools.command.install import install

with open('contrib/requirements/requirements.txt') as f:
    requirements = f.read().splitlines()

with open('contrib/requirements/requirements-hw.txt') as f:
    requirements_hw = f.read().splitlines()

version = imp.load_source('version', 'electrum/version.py')

if sys.version_info[:3] < (3, 4, 0):
    sys.exit("Error: EXOS-Electrum requires Python version >= 3.4.0...")

data_files = []

if platform.system() in ['Linux', 'FreeBSD', 'DragonFly']:
    parser = argparse.ArgumentParser()
    parser.add_argument('--root=', dest='root_path', metavar='dir', default='/')
    opts, _ = parser.parse_known_args(sys.argv[1:])
    usr_share = os.path.join(sys.prefix, "share")
    icons_dirname = 'pixmaps'
    if not os.access(opts.root_path + usr_share, os.W_OK) and \
       not os.access(opts.root_path, os.W_OK):
        icons_dirname = 'icons'
        if 'XDG_DATA_HOME' in os.environ.keys():
            usr_share = os.environ['XDG_DATA_HOME']
        else:
            usr_share = os.path.expanduser('~/.local/share')
    data_files += [
        (os.path.join(usr_share, 'applications/'), ['exos-electrum.desktop']),
        (os.path.join(usr_share, icons_dirname), ['icons/exos-electrum.png'])
    ]

extras_require = {
    'hardware': requirements_hw,
    'fast': ['pycryptodomex'],
    'gui': ['pyqt5'],
}
extras_require['full'] = [pkg for sublist in list(extras_require.values()) for pkg in sublist]


class CustomInstallCommand(install):
    def run(self):
        install.run(self)
        # potentially build Qt icons file
        try:
            import PyQt5
        except ImportError:
            pass
        else:
            try:
                path = os.path.join(self.install_lib, "electrum/gui/qt/icons_rc.py")
                if not os.path.exists(path):
                    subprocess.call(["pyrcc5", "icons.qrc", "-o", path])
            except Exception as e:
                print('Warning: building icons file failed with {}'.format(e))


setup(
    name="EXOS-Electrum",
    version=version.ELECTRUM_VERSION,
    install_requires=requirements,
    extras_require=extras_require,
    packages=[
        'electrum_exos',
        'electrum_exos.gui',
        'electrum_exos.gui.qt',
        'electrum_exos.plugins',
    ] + [('electrum_exos.plugins.'+pkg) for pkg in find_packages('electrum_exos/plugins')],
    package_dir={
        'electrum_exos': 'electrum'
    },
    package_data={
        '': ['*.txt', '*.json', '*.ttf', '*.otf'],
        'electrum_exos': [
            'wordlist/*.txt',
            'locale/*/LC_MESSAGES/electrum.mo',
        ],
    },
    scripts=['electrum/exos-electrum'],
    data_files=data_files,
    description="Lightweight EXOS Wallet",
    author="OpenExO and ExO Economy Developers, Fluid Chains Devs",
    author_email="turcol@gmail.com",
    license="MIT Licence",
    url="https://economy.openexo.com",
    long_description="""Lightweight EXOS Wallet""",
    cmdclass={
        'install': CustomInstallCommand,
    },
)
