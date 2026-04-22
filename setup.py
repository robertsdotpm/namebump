from setuptools import setup, find_packages

setup(
    name="namebump",
    version="0.0.8",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=["aionetiface", "ecdsa", "aiomysql"],
)
