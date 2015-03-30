from gssapi_bindings_gen.processor import FuncProcessor
from gssapi_bindings_gen.languages.cython import CythonCodeGenerator

gen = CythonCodeGenerator(FuncProcessor)

if __name__ == '__main__':
    import sys

    if len(sys.argv) == 2:
        raw_import_path = sys.argv[1]
        if '#' in raw_import_path:
            import_path, import_func = raw_import_path.split('#')
        else:
            import_path = raw_import_path
            import_func = None

        __import__(import_path)

        module = sys.modules[import_path]
        if import_func is not None:
            func = getattr(module, import_func)
            code = gen.code_for_function(func)
        else:
            code = gen.code_for_module(module)

        print(code)
    else:
        sys.exit("You must supply a package or a method")
