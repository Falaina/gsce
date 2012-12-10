from setuptools import setup

setup(
    name='PersonA ～オペラ座の怪人～ Translation Tools',
    version='0.1.0',
    author='Falaina',
    author_email='falaina@falaina.net',
    url='http://github.com/Falaina/gscetools',
    packages=['gsce'],
    description='Tools for unpacking/repacking Persona ～オペラ座の怪人～ files',
    install_requires=[
        'numpy==1.6.2',
        'six==1.2.0',
        'path.py>=2.4.1',
        'bitstring>=3.0.2'
    ]
)
