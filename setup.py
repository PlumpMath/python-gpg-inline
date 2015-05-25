from setuptools import setup, find_packages
from os.path import join, dirname

readme_file = 'README.md'


def _get_readme():
    with open(join(dirname(__file__), readme_file)) as f:
        return f.read()


setup(name='package-name',
      version='0.1',
      packages=find_packages(),
      # install_requires=[],
      author='Your Name',
      author_email='you@example.com',
      description='Short description',
      long_description=_get_readme(),
      license='some license[1]',
      url='https://www.example.com/your-project',
      # Tune to taste:
      classifiers=[
          # See[2]
          'Development Status :: 3 - Alpha',
          # Intended Audience :: Some audience
          # License :: OSI Approved :: Some open source license
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

# [1] There's a good list of Open Source licenses here:
#
#   http://opensource.org/licenses/alphabetical
#
# The license field should be the same as the abbreviation in parens
# on that page.
#
# [2] https://pypi.python.org/pypi?:action=list_classifiers
