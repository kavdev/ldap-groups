#!/usr/bin/env python

import os
from unittest import TestLoader, TextTestRunner

if __name__ == "__main__":
    test_suite = TestLoader().discover(os.path.join('tests'))
    TextTestRunner(verbosity=1).run(test_suite)
