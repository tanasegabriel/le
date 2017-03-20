from setuptools import setup

setup(name='logentries',
      version="1.4.41",
      description='Logentries Linux agent',
      author='Logentries',
      author_email='hello@logentries.com',
      url='https://www.logentries.com/',
      package_dir={'logentries': 'src'},
      packages=['logentries'],
      install_requires=['future==0.16.0', 'configparser==3.5.0', 'filters>=1.1.4', 'requests>=2.9.1', 'formats==0.1.1'],
      entry_points={
          'console_scripts': [
              'le = logentries.le:main'
          ]
      }
)
