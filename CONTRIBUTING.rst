============
Contributing
============

Contributions are welcome, and they are greatly appreciated! Every
little bit helps, and credit will always be given. This document was adapted
from https://github.com/kavdev/dj-stripe/CONTRIBUTING.rst

You can contribute in many ways:

Types of Contributions
----------------------

Report Bugs
~~~~~~~~~~~

Report bugs at https://github.com/kavdev/ldap-groups/issues.

If you are reporting a bug, please include:

* The version of python and Django you're running
* Detailed steps to reproduce the bug.

Fix Bugs
~~~~~~~~

Look through the GitHub issues for bugs. Anything tagged with "bug"
is open to whoever wants to fix it.

Implement Features
~~~~~~~~~~~~~~~~~~

Look through the GitHub issues for features. Anything tagged with "feature"
is open to whoever wants to implement it.

Submit Feedback
~~~~~~~~~~~~~~~

The best way to send feedback is to file an issue at https://github.com/kavdev/ldap-groups/issues.

If you are proposing a feature:

* Explain in detail how it would work.
* Keep the scope as narrow as possible, to make it easier to implement.
* Remember that this is a volunteer-driven project, and that contributions are welcome.

Get Started!
------------

Ready to contribute? Here's how to set up `ldap-groups` for local development.

1. Fork the `ldap-groups` repo on GitHub.
2. Clone your fork locally::

    $ git clone git@github.com:your_name_here/ldap-groups.git

3. Install your local copy into a virtualenv. Assuming you have virtualenvwrapper
   installed, this is how you set up your fork for local development::

    $ mkvirtualenv ldap-groups
    $ cd ldap-groupss/
    $ python setup.py develop

4. Create a branch for local development::

    $ git checkout -b name-of-your-bugfix-or-feature

   Now you can make your changes locally.

5. When you're done making changes, check that your changes pass the tests. runtests
   will output both command line and html coverage statistics and will warn you if
   your changes caused code coverage to drop.::

    $ pip install -r requirements/test.txt
    $ python runtests.py

6. Commit your changes and push your branch to GitHub::

    $ git add .
    $ git commit -m "Your detailed description of your changes."
    $ git push origin name-of-your-bugfix-or-feature

7. Submit a pull request through the GitHub website.

Pull Request Guidelines
-----------------------

Before you submit a pull request, check that it meets these guidelines:

1. The pull request should include tests.
2. The pull request must not drop code coverage below the current level.
3. If the pull request adds functionality, documentation should be included. Any
   new functions should include docstrings.
4. The pull request should work for Python 2.7, 3.4, and 3.5. Check
   https://travis-ci.org/kavdev/ldap-groups/pull_requests
   and make sure that the tests pass for all supported versions.
