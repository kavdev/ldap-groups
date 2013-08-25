from distutils.core import setup

setup(
    name='ldap-groups',
    version='1.0.0',
    author='Alex Kavanaugh',
    author_email='kavanaugh.development@outlook.com',
    packages=['ldap-groups'],
    url='https://bitbucket.org/alex_kavanaugh/ldap-groups/',
    license='GNU LGPL (http://www.gnu.org/licenses/lgpl.html)',
    description="A python LDAP group management abstraction.",
    long_description=open('README.rst').read(),
    install_requires=[
        "Django>=1.5.2",
        "python-ldap==2.4.13",
    ],
)
