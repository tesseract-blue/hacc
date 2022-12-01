from setuptools import setup, find_packages

setup(
    name="hacc",
    version="0.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=["ipykernel", "pytest", "cryptography"],
)
