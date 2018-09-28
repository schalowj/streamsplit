import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="streamsplit",
    version="0.1.0",
    author="J.A. Schalow",
    author_email="schalowj@gmail.com",
    description="A utility to extract TCP streams from (large) pcap files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/schalowj/streamsplit",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
    ],
)
