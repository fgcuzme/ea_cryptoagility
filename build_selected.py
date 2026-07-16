from setuptools import setup
from Cython.Build import cythonize

# lista de archivos a recompilar
files_to_build = [
    "propagacionTx_light.py",
    "cluster.py",
    "ea_cryptoagility/crypto_module.py"
]

setup(
    ext_modules=cythonize(
        files_to_build,
        compiler_directives={"language_level":"3"}
    ),
    script_args=["build_ext", "--inplace"]
)
