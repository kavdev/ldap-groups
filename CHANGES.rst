.. :changelog:

Changes
=======

4.2.2 (2016-09-14)
------------------

* pep8 and project structure changes
* added support for using ADGroup as a context_manager #2


4.2.1 (2015-12-23)
------------------

* A KeyError is no longer thrown when a member attribute can't be retrieved. None is returned instead. (Thanks @willson556)

4.2.0 (2015-09-01)
------------------

* added get_tree_members method

4.1.1 (2015-08-28)
------------------

* updated dependency, escape_query bugfixes

4.1.0 (2015-03-25)
------------------

* all filter queries are now properly escaped in accordance with the LDAP spec (except the NUL character)

4.0.0 (2014-11-10)
------------------

* added abilily to configure search bases, search for user/group by now specified attribute
* added child add/remove methods, refactored method/class signatures, added attribute caching, all lookups are now paged

3.0.4 (2014-10-20)
------------------

* bugfix, refactoring

3.0.3 (2014-10-13)
------------------

* bugfix

3.0.2 (2014-10-08)
------------------

* bugfix

3.0.1 (2014-10-08)
------------------

* bugfix

3.0.0 (2014-10-03)
------------------

* Switched to python3-ldap

2.5.3 (2014-09-15)
------------------

* Fixed child search, added custom search function

2.5.2 (2014-09-04)
------------------

* Fixed Issue #2, fixed readme examples

2.5.1 (2014-08-31)
------------------

* Fixed python-ldap dependency restriction (now >=)

2.5.0 (2014-08-30)
------------------

* Added group attribute and tree traversal methods

2.0.0 (2014-08-30)
------------------

* Removed django dependency

1.0.1 (2013-09-05)
------------------

* Bugfix - Nonexistent user can also throw a TypeError

1.0.0 (2013-08-26)
------------------

* Initial release