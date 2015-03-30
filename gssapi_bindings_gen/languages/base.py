import re
import inspect
import collections

from gssapi_bindings_gen.utils import NotNone

class BaseHook(object):
    def __init__(self, arg_name):
        self.arg_name = arg_name

    def before_call(self):
        return None

    def for_call(self):
        return None

    def after_call(self):
        return None

    def for_success(self):
        return (None, None)

    def for_error(self):
        return None


class CodeLookup(object):
    # lookup
    def is_known_type(self, python_type):
        pass

    def as_c_type(self, python_type):
        pass

    def transformer_for_type(self, python_type):
        pass

    def inverse_transformer_for_type(self, c_type):
        pass

    def transformer(self, func_name, *args, **kwargs):
        pass

    def make_transformer_args(self, func_name, args, param_type, can_be_none):
        pass

    def has_transformer(self, func_name):
        pass

    def inverse_transformer(self, func_name, *args):
        pass

    def has_inverse_transformer(self, func_name):
        pass

    def cleanup_expression(self, cleanup_type):
        pass

    def hook(self, hook_name):
        pass


class CodeGenerator(object):
    LOOKUP_CLS = None

    def __init__(self, processor_cls):
        self._processor = processor_cls(self.LOOKUP_CLS())

    def code_lines(self, target_func, argspecs):
        pass

    def preamble(self):
        pass

    def postamble(self):
        pass

    def generate_func_line(self, target_func):
        pass

    def wrap_doc_lines(self, lines):
        pass

    def docs_func_signature(self, func_line, target_func, sig):
        func_params = []
        for param_name, param in sig.parameters.items():
            param_text = param_name
            if param.default is not inspect.Parameter.empty:
                param_text += '=%s' % param.default

            func_params.append(param_text)

        if isinstance(sig.return_annotation, str):
            ret_text = ' -> %s' % sig.return_annotation
        elif sig.return_annotation is not inspect.Signature.empty:
            ret_text = ' -> %s' % sig.return_annotation.__name__
        else:
            ret_text = ''

        return 'def %s(%s)%s' % (target_func.__name__, ', '.join(func_params),
                                 ret_text)

    def docs_for_function(self, func_line, base_docs, input_docs, target_func):
        sig = inspect.signature(target_func)

        sig_line = self.docs_func_signature(func_line, target_func, sig)

        lines = [sig_line]

        doc_lines = [line.rstrip() for line in base_docs.rstrip().splitlines()]

        base_indent = len(doc_lines[0]) - len(doc_lines[0].lstrip())
        if base_indent == 0:
            base_indent = len(doc_lines[1]) - len(doc_lines[1].lstrip())

        doc_lines = [line[base_indent:] for line in doc_lines]

        raise_lines = None
        if 'Raises:' in doc_lines:
            raises_starts = doc_lines.index('Raises:')
            raises_lines = doc_lines[raises_starts:]
            doc_lines = doc_lines[:raises_starts]

        lines.extend(doc_lines)

        if input_docs:
            lines.append('Args:')

            for arg_name in sig.parameters.keys():
                arg_help = input_docs.get(arg_name, '')
                arg_type = sig.parameters[arg_name].annotation

                if isinstance(sig.return_annotation, NotNone):
                    arg_type = arg_type.type
                    arg_help = '*(Not None)* ' + arg_help
                elif arg_type is inspect.Parameter.empty:
                    arg_type = None

                arg_type_str = ''
                if arg_type is not None:
                    if isinstance(arg_type, type):
                        arg_type_str = ' (%s)' % arg_type.__name__
                    else:
                        arg_type_str = ' (%s)' % arg_type

                lines.append('    %s%s: %s' % (arg_name, arg_type_str, arg_help))

        if sig.return_annotation is not inspect.Signature.empty:
            lines.append('')
            lines.append('Returns:')
            if isinstance(sig.return_annotation, str):
                lines.append('    %s' % sig.return_annotation)
            else:
                lines.append('    %s' % sig.return_annotation.__name__)

        if raises_lines:
            lines.append('')
            lines.extend(raises_lines)

        return self.wrap_doc_lines(lines)

    def code_for_function(self, func):
        func_name = func.__name__
        processed_func = self._processor.process(func)

        func_line = self.generate_func_line(func)

        code_lines_raw = self.code_lines(func, processed_func)

        code_lines = ['    ' + line for line in code_lines_raw]
        doc_lines = ['    ' + line for line in
                     self.docs_for_function(
                         func_line, processed_func.func_docs,
                         processed_func.input_docs, func)]

        return '\n'.join([func_line] + doc_lines + code_lines)

    def code_for_module(self, module):
        funcs = inspect.getmembers(module, inspect.isfunction)

        filtered_funcs = [func for func_name, func in funcs
                          if func.__module__ == module.__name__]

        module_code = self.preamble();
        for func in filtered_funcs:
            code = self.code_for_function(func)
            module_code += code
            module_code += "\n\n\n"

        module_code += self.postamble()

        return module_code

def replace_vars(lines, **varspec):
    if isinstance(lines, str):
        lines = [lines]
        was_str = True
    else:
        was_str = False

    def replace_func(m):
        return varspec.get(m.group(2), m.group(0))

    for varname, varval in varspec.items():
        replace_re = r'\$({)?([a-z]+)(?(1)})'
        lines = [re.sub(replace_re, replace_func, line) for line in lines]

    if was_str:
        return lines[0]
    else:
        return lines
