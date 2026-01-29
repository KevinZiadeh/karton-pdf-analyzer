from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("karton-pdf-analyzer")

except PackageNotFoundError:
    __version__ = "unknown"

finally:
    del version, PackageNotFoundError
