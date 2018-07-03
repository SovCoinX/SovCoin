from distutils.core import setup
setup(name='SOVspendfrom',
      version='1.0',
      description='Command-line utility for sov "coin control"',
      author='Gavin Andresen',
      author_email='gavin@sovfoundation.org',
      requires=['jsonrpc'],
      scripts=['spendfrom.py'],
      )
