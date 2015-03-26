import os
from setuptools import setup


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='ldap-groups',
    version='4.1.0',
    author='Alex Kavanaugh',
    author_email='kavanaugh.development@outlook.com',
    description="A python/django Active Directory group management abstraction that uses python3-ldap as a backend for cross-platform compatibility.",
    long_description=read('README.rst'),
    keywords="ldap active directory ldap-groups groups adgroups python django ad",
    license='GNU LGPL (http://www.gnu.org/licenses/lgpl.html)',
    url='https://bitbucket.org/kavanaugh_development/ldap-groups/',
    packages=['ldap_groups'],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP",
        "Topic :: Utilities",
    ],
    install_requires=[
        "python3-ldap>=0.9.6",
    ],
)
