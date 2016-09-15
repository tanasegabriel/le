import os
from setuptools import setup

setup(name='logentries',
      version="1.4.39",
      description='Logentries Linux agent',
      author='Logentries',
      author_email='hello@logentries.com',
      url='https://www.logentries.com/',
      package_dir={'logentries': 'src'},
      packages=['logentries'],
      entry_points={
          'console_scripts': [
              'le = logentries.le:main'
          ]
      }
)
