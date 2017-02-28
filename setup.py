import os
from setuptools import setup

setup(name='logentries',
      version="1.4.41",
      description='Logentries Linux agent',
      author='Logentries',
      author_email='hello@logentries.com',
      url='https://www.logentries.com/',
      package_dir={'logentries': 'src'},
      packages=['logentries'],
      install_requires=['futures==3.0.5'],
      entry_points={
          'console_scripts': [
              'le = logentries.le:main'
          ]
      }
)
