'''
muddy: IETF MUD file generator and validator

Copyright 2018, dinesha ranathunga.
Licensed under MIT.
'''
import sys
from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

# This is a plug-in for setuptools that will invoke py.test
# when you run python setup.py test
class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest  # import here, because outside the required eggs aren't loaded yet
        sys.exit(pytest.main(self.test_args))


version = "0.14"

setup(name="muddy",
      version=version,
      description="IETF MUD file generator and validator",
      #long_description=open("README.rst").read(),

      # List of packages that this one depends upon:
      install_requires = [
         'netaddr==0.7.10',
         'mako==0.8',
         'ipaddr==2.1.11',
         ],

      classifiers=[ # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 1 - Planning',
        'Programming Language :: Python'
        'Intended Audience :: Science/Research',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
        'Topic :: System :: Networking',
        'Topic :: Scientific/Engineering :: Mathematics',
      ],

      keywords="", # Separate with spaces
      author="dinesha ranathunga",
      author_email="dinesha.ranathunga@adelaide.edu.au",
      url="",
      license="MIT",
      packages=find_packages(exclude=['examples', 'tests']),
      include_package_data=True,
      zip_safe=True,
      download_url = (""),
      tests_require=['pytest'],
      cmdclass={'test': PyTest},
      
      # TODO: List executable scripts, provided by the package (this is just an example)
      entry_points = {
         'console_scripts': [
             'muddy = muddy.console_script:console_entry',
        ],
      }
)
