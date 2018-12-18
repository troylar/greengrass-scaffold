import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="greengrass-sod",
    version='0.0.4',
    author="Troy Larson",
    author_email="troylar@gmail.com",
    description="Easy Greengrass Scaffolding framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/troylar/greengrass-sod",
    packages=setuptools.find_packages(),
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)
