from distutils.core import setup

LONGDESC="""Client taxonomy.
Identifies a wifi chipset based on the options it includes
in several types of Wifi management frames.
"""

setup(name='taxonomy',
      version='1.0',
      description='Client identification.',
      license='Apache',
      author='Denton Gentry',
      author_email='dgentry@google.com',
      url='https://gfiber.googlesource.com/',
      download_url='https://gfiber.googlesource.com/vendor/google/platform/',
      long_description=LONGDESC,
      package_dir={'taxonomy': ''},
      packages=['taxonomy'],
      )
