from distutils.core import setup

setup(
    name='ldap-groups',
    version='1.0.1',
    author='Alex Kavanaugh',
    author_email='kavanaugh.development@outlook.com',
    packages=['ldap_groups'],
    url='https://bitbucket.org/alex_kavanaugh/ldap-groups/',
    license='GNU LGPL (http://www.gnu.org/licenses/lgpl.html)',
    description="A django Active Directory group management abstraction that uses python-ldap as a backend for cross-platform compatibility.",
    long_description=open('README.rst').read(),
    install_requires=[
        "Django>=1.5.2",
        "python-ldap==2.4.13",
    ],
)
