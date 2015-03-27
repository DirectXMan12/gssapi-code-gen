from gssapi_bindings_gen.processor import FuncProcessor
from gssapi_bindings_gen.languages.cython import CythonCodeGenerator

gen = CythonCodeGenerator(FuncProcessor)

if __name__ == '__main__':
    import sys

    if len(sys.argv) == 2:
        __import__(sys.argv[1])
        print(gen.code_for_module(sys.modules[sys.argv[1]]))
