
import unittest

def test_suite():
    import tests.test_gpg

    suite = unittest.TestSuite()

    suite.addTest(tests.test_gpg.test_suite())

    return suite