from setuptools import setup, find_packages
from os.path import join, dirname

readme_file = 'README.md'


def _get_readme():
    with open(join(dirname(__file__), readme_file)) as f:
        return f.read()


setup(name='gpg-inline',
      version='0.1',
      packages=find_packages(),
      install_requires=['python-gnupg'],
      author='Ian Denhardt',
      author_email='ian@zenhack.net',
      description='Library for extracting inline pgp blobs with gpg',
      long_description=_get_readme(),
      license='GPLv3+',
      url='https://www.example.com/your-project',
      # Tune to taste:
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.0',
          'Programming Language :: Python :: 3.1',
          'Programming Language :: Python :: 3.2',
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
      ])
