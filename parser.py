#from parcon import *
import inspect
import re
import collections

from method_template import NotNone

_WRAPPER_TYPE_TRANSFORMERS = {
    'Name': 'inplace($.raw_name)',
    'Creds': 'inplace($.raw_cred)',
    'ChannelBindings': 'default(GSS_C_NO_CHANNEL_BINDINGS; $.__cvalue__()); cleanup(free_non_default)',
    'SecurityContext': 'inplace($.raw_ctx)'
}

_WRAPPER_TYPE_PY_TO_C_TYPES = {
    'ChannelBindings': 'gss_channel_bindings_t'
}

_WRAPPER_TYPE_INVERSE_TRANSFORMERS = {
    #          ((initval,     output initializer,           block code      ), inline code )
    'gss_OID': (('OID()', ['cdef OID $o = $initval'], ['$o.raw_oid = $i[0]']), '$o'),
    'gss_name_t': (('Name()', ['cdef Name $o = $initval'], ['$o.raw_name = $i']), '$o'),
    'gss_cred_id_t': (('Creds()', ['cdef Creds $o = $initval'], ['$o.raw_cred = $i']), '$o')
}

def _default_transformer(def_val, otherwise, explict_branch=False):
    if explict_branch in ('True', 'explicit'):
        return ([
            '$typedecl',
            'if $i is None:',
            '    $o = %s' % def_val,
            'else:',
            '    $o = %s' % otherwise
        ], '$o', None)
    else:
        return ([
            '$typedecl = %s' % def_val,
            'if $i is not None:',
            '    $o = %s' % otherwise
        ], '$o', None)

def _bytes_to_buffer_transformer(input_expr):
    return ([
        'cdef gss_buffer_desc $o = gss_buffer_desc(len({0}), {0})'.format(input_expr)
    ], '&$o', None)

# should be functions which return (block code, base inline code, default cleanup)
_TRANSFORMER_FUNCS = {
    'default': _default_transformer,
    'bytes_to_buffer': _bytes_to_buffer_transformer
}

_INVERSE_TRANSFORMER_FUNCS = {}

_CLEANUP_EXPRS= {
    'free_non_default': ['if $o is None:', '    free($i)']
}

_HOOKS = {
}

# name: normal-number-of-args
_TRANSFORMERS_WITH_IMPLIED_ARG = {'default': 2}

_TRANSFORMER_RE = re.compile('^(\w+)\((.+?)\)(; inplace\((.+)\))?(; cleanup\((.+)\))?$')

def extract_info(target_func):
    sig = inspect.signature(target_func)

    doc_str = target_func.__doc__

    input_args_start = doc_str.index('Input Args:\n') + 12

    if 'Success On:\n' in doc_str:
        success_on_start = doc_str.index('Success On:\n') + 12
    else:
        success_on_start = len(doc_str) + 12

    if 'Output Args:\n' in doc_str:
        output_args_start = doc_str.index('Output Args:\n') + 13
    else:
        output_args_start = success_on_start + 1

    input_args_raw = doc_str[input_args_start:output_args_start - 13]
    input_args_lines = [line.strip() for
                        line in input_args_raw.splitlines()
                        if line and not line.isspace()]

    input_arg_spec, input_arg_help = extract_input_info(input_args_lines, sig)


    if output_args_start != success_on_start + 1:
        output_args_raw = doc_str[output_args_start:success_on_start - 12]
        output_args_lines = [line.strip() for
                            line in output_args_raw.splitlines()
                            if line and not line.isspace()]
        output_arg_spec = extract_output_info(output_args_lines, sig)
    else:
        output_arg_spec = {}

    if success_on_start != len(doc_str) + 12:
        success_on_raw = doc_str[success_on_start:]
        success_on = [line.strip() for line in success_on_raw.splitlines()
                      if line and not line.isspace()]
    else:
        success_on = ['GSS_S_COMPLETE']

    return (input_arg_spec, input_arg_help, output_arg_spec, success_on, doc_str[:input_args_start - 12])


def extract_output_info(output_args_lines, sig):
    output_arg_spec = collections.OrderedDict()
    positional_ind = -1

    for line in output_args_lines:
        parts = line.split(' -> ')
        if ' #' in parts[-1]:
            doc_index = parts[-1].index('#')
            parts[-1] = parts[-1][:doc_index].rstrip()
            # TODO(directxman12): support docs on output args

        if len(parts) > 2:
            raise ValueError('Output argspecs must have at most 2 parts')

        if parts[0].endswith(']'):
            temp_type_start = parts[0].index('[')
            arg_name = parts[0][:temp_type_start - 1]

            type_annotation_raw = parts[0][temp_type_start + 1:-1]
            annot_parts = type_annotation_raw.split('; ')

            if annot_parts[0].startswith('nullable: '):
                annot_parts[0] = annot_parts[0][10:]
                is_nullable = True
            else:
                is_nullable = False

            if len(annot_parts) == 2:
                temporary_type = annot_parts[0]
                c_transformer = annot_parts[1].replace('$', '$i')
                initial_value = None
            elif len(annot_parts) == 3:
                temporary_type = annot_parts[0]
                initial_value = annot_parts[1]
                c_transformer = annot_parts[2].replace('$', '$i')
            else:
                raise ValueError("Output type annotations must have 2 or 3 parts")
        else:
            arg_name = parts[0]
            temporary_type = None
            initial_value = None
            c_transformer = None
            is_nullable = False

        if len(parts) == 1:
            # we have a known wrapper type
            if temporary_type is None:
                # this parameter is also an input parameter
                py_transformer = None
                py_inline_transformer = '$o'
            else:
                py_transformer, py_inline_transformer = _WRAPPER_TYPE_INVERSE_TRANSFORMERS.get(temporary_type, (None, '$i'))

            hook = None

        elif parts[0] == ';':
            positional_ind += 1
            output_arg_spec[positional_ind] = {'name': None,
                                               'py_inline_transformer': parts[1],
                                               'py_transformer': None,
                                               'temporary_type': None,
                                               'initial_value': None,
                                               'c_transformer': None,
                                               'hook': None}
            continue
        else:
            if parts[1].startswith('; hook('):
                py_transformer = None
                py_inline_transformer = None

                hook_name = parts[1][7:-1]
                hook = _HOOKS[hook_name]
            else:
                hook = None
                func_match = _TRANSFORMER_RE.match(parts[1])
                if (func_match is not None and
                        func_match.group(1) in _INVERSE_TRANSFORMER_FUNCS):
                    func_name = func_match.group(1)

                    func_params_raw = func_match.group(2)
                    func_params = [p.strip().replace('$', '$i') for p in func_params_raw.split(';')]

                    py_transformer, py_inline_transformer = _INVERSE_TRANSFORMER_FUNCS[func_name](*func_params)
                else:
                    py_inline_transformer = parts[1].replace('$', '$o')
                    py_transformer = None

        output_arg_spec[arg_name] = {'name': arg_name,
                                     'py_inline_transformer': py_inline_transformer,
                                     'py_transformer': py_transformer,
                                     'temporary_type': temporary_type,
                                     'initial_value': initial_value,
                                     'c_transformer': c_transformer,
                                     'hook': hook,
                                     'is_nullable': is_nullable}


    return output_arg_spec

def extract_input_info(input_args_lines, sig):

    input_arg_spec = collections.OrderedDict()
    last_name = None
    input_arg_help = {}
    for line in input_args_lines:
        if line.startswith('# '):
            input_arg_help[last_name] += line[2:]
            continue

        parts = line.split(' -> ')
        if ' # ' in parts[-1]:
            doc_index = parts[-1].index(' # ')
            doc_str = parts[-1][doc_index + 3:].strip()
            parts[-1] = parts[-1][:doc_index].rstrip()
        else:
            doc_str = ''

        parts = [part.strip() for part in parts]

        arg_name = last_name = parts[0]
        arg_sig = sig.parameters[arg_name]
        arg_spec = {'name': arg_name}
        input_arg_help[arg_name] = doc_str

        if isinstance(arg_sig.annotation, NotNone):
            arg_type = arg_sig.annotation.type
        else:
            arg_type = arg_sig.annotation

        # extract initial info
        if len(parts) == 1:
            # we have 'known_wrapper_type_param'
            arg_transformer = _WRAPPER_TYPE_TRANSFORMERS[arg_type]

            if arg_transformer.startswith('inplace('):
                arg_spec['temporary_type'] = None
            else:
                arg_spec['temporary_type'] = _WRAPPER_TYPE_PY_TO_C_TYPES[arg_type]

            arg_spec['inline_transformer'] = None
            arg_spec['transformer'] = arg_transformer
            arg_spec['cleanup'] = None
        elif len(parts) == 2:
            if parts[1].startswith('['):
                temp_type_end = parts[1].index(']')
                temporary_type = parts[1][1:temp_type_end]
                dollar_expr = parts[1][temp_type_end + 1:].strip()
            else:
                temporary_type = None
                dollar_expr = parts[1]

            arg_spec['temporary_type'] = temporary_type
            arg_spec['transformer'] = dollar_expr
            arg_spec['inline_transformer'] = None
            arg_spec['cleanup'] = None
        else:
            raise ValueError("Input argspecs have at most 2 parts")

        # convert the partial $-expression into a full dollar-expression
        if arg_spec['inline_transformer'] is not None:
            arg_spec['inline_transformer'] = arg_spec['inline_transformer'].replace('$', '$i')

        if arg_spec['transformer'] is not None:
            arg_spec['transformer'] = arg_spec['transformer'].replace('$', '$i')

            # second, check for functions
            func_match = _TRANSFORMER_RE.match(arg_spec['transformer'])
            if func_match is not None:
                if func_match.group(1) == 'inplace':
                    inline_transformer = func_match.group(2)  # $ already replaced above
                    arg_spec['inline_transformer'] = inline_transformer
                    arg_spec['transformer'] = None
                else:
                    func_name = func_match.group(1)

                    func_params_raw = func_match.group(2)
                    func_params = [p.strip() for p in func_params_raw.split(';')]

                    normal_num_args = _TRANSFORMERS_WITH_IMPLIED_ARG.get(func_name)
                    if (normal_num_args is not None and
                            len(func_params) < normal_num_args and
                            arg_type in _WRAPPER_TYPE_TRANSFORMERS):
                        extra_arg = _WRAPPER_TYPE_TRANSFORMERS[arg_type]
                        func_params.append(extra_arg.replace('$', '$i'))

                    full_transformer, base_inline, default_cleanup = _TRANSFORMER_FUNCS[func_name](*func_params)

                    arg_spec['transformer'] = full_transformer

                    if func_match.group(3) is not None:
                        # $ == $o by default, so it wouldn't make sense to have a $o
                        # in the inline transformer, so we only need to check for $oi
                        inline_transformer = func_match.group(4).replace('$', base_inline)
                        inline_transformer = inline_transformer.replace('$oi', '$i')
                        arg_spec['inline_transformer'] = inline_transformer
                    else:
                        arg_spec['inline_transformer'] = base_inline

                    if func_match.group(5) is not None:
                        cleanup_func_name = func_match.group(6)
                        arg_spec['cleanup'] = _CLEANUP_EXPRS[cleanup_func_name]
                    else:
                        arg_spec['cleanup'] = default_cleanup
            else:
                # if we just have an expression, turn it into an assignment
                arg_spec['transformer'] = ['$o = %s' % arg_spec['transformer']]

        # TODO(directxman12): support switch statement syntax

        input_arg_spec[arg_name] = arg_spec

    return (input_arg_spec, input_arg_help)


def _replace_lines(lines, val, repl):
    return [line.replace(val, repl) for line in lines]

def input_argspec_to_code(argspec):
    transformer = argspec['transformer']
    inline_transformer = argspec['inline_transformer']

    output_name = 'raw_%s' % argspec['name']
    if transformer is not None:
        transformer = _replace_lines(transformer, '$i', argspec['name'])

        type_decl = 'cdef %s %s' % (argspec['temporary_type'], output_name)

        transformer = _replace_lines(transformer, '$o', output_name)
        transformer = _replace_lines(transformer, '$typedecl', type_decl)

    inline_transformer = argspec.get('inline_transformer') or '$o'
    inline_transformer = inline_transformer.replace('$o', output_name)
    inline_transformer = inline_transformer.replace('$i', argspec['name'])

    cleanup_code = argspec['cleanup']
    if cleanup_code is not None:
        cleanup_code = _replace_lines(cleanup_code, '$o', output_name)
        cleanup_code = _replace_lines(cleanup_code, '$i', argspec['name'])

    # TODO(directxman12): last argument is cleanup code, provide method for supplying it
    return (transformer, inline_transformer, cleanup_code)

def output_argspec_to_code(argspec):
    if argspec['hook'] is None:
        return _normal_output_argspec_to_code(argspec)
    else:
        hook = argspec['hook'](argspec['name'])
        return (None, None, None, None, None, hook)

def _normal_output_argspec_to_code(argspec):
    prep_line = None
    if argspec['name']:
        input_name = 'raw_%s' % argspec['name']
        if argspec['temporary_type'] is not None:
            prep_line = 'cdef %s %s' % (argspec['temporary_type'], input_name)
            if argspec['initial_value'] is not None:
                prep_line += ' = %s' % argspec['initial_value']

        c_transformer = argspec['c_transformer']
        if c_transformer is not None:
            c_transformer = c_transformer.replace('$i', input_name)

        if argspec['py_transformer'] is not None:
            default_initval, py_initializer, py_transformer = argspec['py_transformer']

            if argspec['is_nullable']:
                initval = 'None'
            else:
                initval = default_initval

            if py_initializer is not None:
                py_initializer = _replace_lines(py_initializer, '$initval', initval)
                py_initializer = _replace_lines(py_initializer, '$o', argspec['name'])
                py_initializer = _replace_lines(py_initializer, '$i', input_name)

            if py_transformer is not None:
                if argspec['is_nullable']:
                    transformer_indented = ['    ' + line for line in py_transformer]
                    py_transformer = [
                        'if $i is not NULL:',
                        '    $o = %s' % default_initval
                    ] + transformer_indented

                py_transformer = _replace_lines(py_transformer, '$o', argspec['name'])
                py_transformer = _replace_lines(py_transformer, '$i', input_name)
        else:
            py_initializer = None
            py_transformer = None

        py_inline_transformer = argspec['py_inline_transformer']
        py_inline_transformer = py_inline_transformer.replace('$o', argspec['name'])
        py_inline_transformer = py_inline_transformer.replace('$i', input_name)

        return (prep_line, c_transformer, py_initializer, py_transformer, py_inline_transformer, None)
    else:
        return (None, None, None, None, argspec['py_inline_transformer'], None)


def make_cython_func_line(target_func):
    sig = inspect.signature(target_func)

    param_parts = []
    for param_name, param in sig.parameters.items():
        # TODO(directxman12): deal with kw-only args, variadic args, etc
        if param.annotation is not inspect.Parameter.empty:
            if isinstance(param.annotation, NotNone):
                param_part = '%s %s not None' % (param.annotation.type, param_name)
            else:
                param_part = '%s %s' % (param.annotation, param_name)
        else:
            param_part = param_name

        if param.default is not inspect.Parameter.empty:
            param_part += '=%s' % repr(param.default)

        param_parts.append(param_part)

    return 'def %s(%s):' % (target_func.__name__, ', '.join(param_parts))


def make_docs(func_line_raw, docs, arghelp_raw, target_func):
    sig = inspect.signature(target_func)

    func_line = func_line_raw[4:-1]
    if sig.return_annotation is not inspect.Signature.empty:
        if isinstance(sig.return_annotation, str):
            func_line += ' -> %s' % sig.return_annotation
        else:
            func_line += ' -> %s' % sig.return_annotation.__name__

    lines = ['"""' + func_line]
    doc_lines = [line.rstrip() for line in docs.rstrip().splitlines()]

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
    if arghelp_raw:
        lines.append('Args:')

        for arg_name in sig.parameters.keys():
            arg_help = arghelp_raw.get(arg_name, '')
            arg_type = sig.parameters[arg_name].annotation
            if isinstance(arg_type, NotNone):
                arg_type = arg_type.type
            elif arg_type is inspect.Parameter.empty:
                arg_type = None

            arg_type_str = ''
            if arg_type:
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

    lines.append('"""')

    return lines

def gen_code_lines(target_func):
    argspecs, arghelp, outputspecs, success_on, docs = extract_info(target_func)

    code_lines = []
    c_func_args = []
    cleanup_lines = []
    for argspec in argspecs.values():
        block_code, inline_code, cleanup_code = input_argspec_to_code(argspec)
        if block_code is not None:
            code_lines.append('')
            code_lines.append('# convert %s to a C value' % argspec['name'])
            code_lines.extend(block_code)

        if cleanup_code is not None:
            cleanup_lines.append('')
            cleanup_lines.extend(cleanup_code)

        c_func_args.append(inline_code)

    block_output_lines = []
    initializer_lines = []
    return_args = []
    error_args = []
    for argspec in outputspecs.values():
        prep, input_inline_code, initializers, block_code, output_inline_code, hook = output_argspec_to_code(argspec)

        if hook is not None:
            before_lines = hook.before_call()
            if before_lines is not None:
                code_lines.extend(before_lines)

            prep = None

            input_inline_code = hook.for_call()
            initializers = hook.after_call()
            block_code, output_inline_code = hook.for_success()

            err_args = hook.for_error()
            if err_args is not None:
                error_args.extend(err_args)

        if prep is not None:
            code_lines.append(prep)

        if initializers is not None:
            initializer_lines.extend(initializers)

        if block_code is not None:
            block_output_lines.extend(block_code)
            block_output_lines.append('')

        if input_inline_code is not None:
            c_func_args.append(input_inline_code)

        return_args.append(output_inline_code)

    code_lines.append('')
    code_lines.append('cdef OM_uint32 maj_stat, min_stat')

    code_lines.append('')
    code_lines.append('with nogil:')

    func_line = '    maj_stat = gss_%s(&min_stat, %s)' % (target_func.__name__, ', '.join(c_func_args))

    code_lines.append(func_line)
    code_lines.append('')

    if cleanup_lines:
        code_lines.extend(cleanup_lines)

    if initializer_lines:
        code_lines.append('')
        code_lines.extend(initializer_lines)

    sig = inspect.signature(target_func)
    if isinstance(sig.return_annotation, str):
        return_line = '    return %s(%s)' % (sig.return_annotation, ', '.join(return_args))
    elif sig.return_annotation is not inspect.Signature.empty:
        return_line = '    return %s' % return_args[0]
    else:
        return_line = None

    if return_line is not None:
        if len(success_on) == 1:
            code_lines.append('if maj_stat == %s:' % success_on[0])
        else:
            code_lines.append('if maj_stat in (%s):' % ', '.join(success_on))

        code_lines.extend(['    ' + line for line in block_output_lines])
        if block_output_lines:
            code_lines.extend('')
            code_lines.append(return_line)

        code_lines.append('else:')
        code_lines.append('    raise GSSError(maj_stat, min_stat%s)' % ', '.join([''] + error_args))
    else:
        if len(success_on) == 1:
            code_lines.append('if maj_stat != %s:' % success_on[0])
        else:
            code_lines.append('if maj_stat not in (%s):' % ', '.join(success_on))

        code_lines.append('    raise GSSError(maj_stat, min_stat%s)' % ', '.join([''] + error_args))

    return (code_lines, arghelp, docs)

def gen_code(target_func, indent=1):
    func_line = make_cython_func_line(target_func)
    code_lines_raw, arghelp_raw, docs_raw = gen_code_lines(target_func)

    code_lines = [('    ' * indent) + line for line in code_lines_raw]
    doc_lines = [('    ' * indent) + line for line in make_docs(func_line, docs_raw, arghelp_raw, target_func)]

    docs_str = '\n'.join(doc_lines)
    code_str = '\n'.join(code_lines)

    return '\n'.join([func_line, docs_str, code_str])

def gen_module(module):
    funcs = inspect.getmembers(module, inspect.isfunction)

    module_code = "# gssapi-gen-code:begin\n\n\n"
    for func in [func for func_name, func in funcs if func.__module__ == module.__name__]:
        code = gen_code(func)
        module_code += code
        module_code += "\n\n\n"

    module_code += "# gssapi-gen-code:end\n"

    return module_code

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


class OutputTokenHook(BaseHook):
    def before_call(self):
        return ['cdef gss_buffer_desc raw_{0} = gss_buffer_desc(0, NULL)'.format(self.arg_name)]

    def for_call(self):
        return '&raw_%s' % self.arg_name

    def after_call(self):
        return (line.format(self.arg_name) for line in [
            '',
            '{0} = None',
            'if raw_{0}.length:',
            '    {0} = raw_{0}.value[:raw_{0}.length]',
            'cdef OM_uint32 tmp_min_stat',
            'gss_release_buffer(&tmp_min_stat, raw_{0})',
            ''
        ])

    def for_success(self):
        return (None, self.arg_name)

    def for_error(self):
        return ['token={0}'.format(self.arg_name)]

_HOOKS['output_token'] = OutputTokenHook


if __name__ == '__main__':
    import sys

    if len(sys.argv) == 2:
        __import__(sys.argv[1])
        print(gen_module(sys.modules[sys.argv[1]]))
