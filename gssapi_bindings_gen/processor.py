import collections
import inspect
import re

from gssapi_bindings_gen.utils import NotNone


ProcessorResult = collections.namedtuple(
    'ProcessorResult', ['input_args', 'input_docs', 'output_args',
                        'success_on', 'func_docs'])



def _find_start(content, header, mandatory=False, offset=0):
    full_header = '%s:\n' % header
    content_partial = content[offset:]
    if full_header in content:
        return content_partial.index(full_header) + len(full_header) + offset
    elif not mandatory:
        return None
    else:
        raise ValueError('Expected to find "%s", but it was missing' % header)


class FuncProcessor(object):
    _DOLLAR_RE = re.compile(r'\$(?![a-z])')
    _TRANSFORMER_RE = re.compile(r'^(?P<func>\w+)\((?P<args>.+?)\)'
                                 r'(; inplace\((?P<inline>.+)\))?'
                                 r'(; cleanup\((?P<cleanup>.+)\))?$')

    def __init__(self, lookup):
        self._lookup = lookup

    def _process_input_line(self, line):
        if line.startswith('# '):  # just doc
            return (True, line[2:].strip())

        parts = line.split(' -> ')

        if len(parts) > 2:
            raise ValueError('Input argspecs have at most two parts '
                             '(got spec "%s")' % ' -> '.join(parts))

        if ' # ' in parts[-1]:
            doc_index = parts[-1].index(' # ')
            doc_str = parts[-1][doc_index + 3:].strip()
            parts[-1] = parts[-1][:doc_index].rstrip()
        else:
            doc_str = None

        arg_name = parts[0]

        try:
            arg_sig = self._param_sigs[arg_name]
        except KeyError:
            raise ValueError("Unknown input parameter '%s'" % arg_name)

        arg_spec = {}

        if isinstance(arg_sig.annotation, NotNone):
            arg_type = arg_sig.annotation.type
            nullable = False
        else:
            arg_type = arg_sig.annotation
            nullable = True


        # handle a known wrapper type
        if len(parts) == 1:
            if arg_type is None:
                raise ValueError('Type of %s was not specified and '
                                 'is needed to infer transformers' % arg_name)

            trans_raw = self._lookup.transformer_for_type(arg_type)
        else:
            trans_raw = parts[1]

        if trans_raw.startswith('['):
            temp_type_end = trans_raw.index(']')
            temporary_type = trans_raw[1:temp_type_end]
            dollar_expr = trans_raw[temp_type_end + 1:].strip()
        else:
            dollar_expr = trans_raw

            if arg_type is None:
                raise ValueError('Type of %s was not specified and is needed'
                                 'to infer temporary types' % arg_name)

            temporary_type = self._lookup.as_c_type(arg_type)

        # extract transformer information
        func_match = self._TRANSFORMER_RE.match(dollar_expr)
        if (func_match is not None and
                (func_match.group('func') == 'inplace' or
                    self._lookup.has_transformer(func_match.group('func')))):
            func_name = func_match.group('func')

            if func_name == 'inplace':
                c_arg_expr = func_match.group('args')
                transformer = None
                cleanup_expr = None
            else:
                func_params_raw = func_match.group('args')
                func_params = [p.strip() for p in func_params_raw.split(';')]

                actual_args, kwargs = self._lookup.make_transformer_args(
                    func_name, func_params, arg_type, nullable)

                transformer, base_c_arg, default_cleanup = (
                    self._lookup.transformer(func_name, *actual_args,
                                             **kwargs))

                if func_match.group('inline') is not None:
                    c_arg_expr = self._DOLLAR_RE.sub(
                        base_c_arg, func_match.group('inline'))
                else:
                    c_arg_expr = base_c_arg

                if func_match.group('cleanup') is not None:
                    cleanup_expr = self._lookup.cleanup_expression(
                        func_match.group('cleanup'))
                else:
                    cleanup_expr = default_cleanup

        else:
            transformer = ['$typedecl', '$o = %s' % dollar_expr]
            c_arg_expr = '$'
            cleanup_expr = None

        # convert $ to $i/$o
        if transformer is not None:
            transformer = [self._DOLLAR_RE.sub('$i', line) for line in transformer]

        c_arg_expr = self._DOLLAR_RE.sub('$o', c_arg_expr)

        arg_spec = {
            'transformer': transformer,
            'c_arg_expr': c_arg_expr,
            'cleanup': cleanup_expr,
            'temporary_type': temporary_type
        }

        return (False, doc_str, arg_name, arg_spec)

    def _process_output_line(self, line):
        parts = line.split(' -> ')

        # TODO(directxman12): support docs on output args
        if len(parts) > 2:
            raise ValueError('Output argspecs have at most two parts')

        name_spec = parts[0]

        hook = None
        is_nullable = False

        # deal with type annotation
        if name_spec.endswith(']'):
            temp_type_start = name_spec.index('[')
            arg_name = name_spec[:temp_type_start - 1]

            type_annotation_expr = name_spec[temp_type_start + 1:-1]
            annotation_parts = type_annotation_expr.split('; ')

            temporary_type = annotation_parts[0]
            if temporary_type.startswith('nullable: '):
                is_nullable = True
                temporary_type = temporary_type[10:]
            else:
                is_nullable = False

            if len(annotation_parts) == 2:
                initial_value = None
                c_arg_expr = annotation_parts[1]
            elif len(annotation_parts) == 3:
                initial_value = annotation_parts[1]
                c_arg_expr = annotation_parts[2]
            else:
                raise ValueError('Output arg type annotations must have '
                                 'either 2 or 3 parts (got type annotation '
                                 '"[%s]")' % '; '.join(annotation_parts))
        elif len(parts) == 1:
            # len 1 not ending in a type annotation means an input parameter
            arg_name = name_spec
            c_arg_expr = None
            temporary_type = None
            initial_value = None

        elif name_spec == ';':
            self._positional_ind += 1
            arg_name = self._positional_ind
            c_arg_expr = None
            temporary_type = None
            initial_value = None

        elif parts[1].startswith('; hook('):
            arg_name = name_spec
            c_arg_expr = None
            temporary_type = None
            initial_value = None

        else:
            raise ValueError('Output arg specs with more than one part '
                             'must have a type annotation (got spec '
                             '"%s"' % ' -> '.join(parts))

        # deal with main transformer
        if len(parts) == 1:
            if temporary_type is None:
                # input parameter
                transformer = None
                return_expr = '$o'
            else:
                # known wrapper type
                transformer, return_expr = (
                    self._lookup.inverse_transformer_for_type(temporary_type))

        elif name_spec == ';':
            transformer = None
            return_expr = parts[1]

        elif parts[1].startswith('; hook('):
            transformer = None
            return_expr = None
            hook_name = parts[1][7:-1]
            hook = self._lookup.hook(hook_name, arg_name)

        else:
            dollar_expr = parts[1]
            func_match = self._TRANSFORMER_RE.match(dollar_expr)
            if (func_match is not None and
                    self._lookup.has_inverse_transformer(
                        func_match.group('func'))):
                func_name = func_match.group('func')
                func_params_raw = func_match.group('args')
                func_params = [p.strip() for p in func_params_raw.split(';')]

                transformer, return_expr  = self._lookup.inverse_transformer(
                    func_name, *func_params)
            else:
                return_expr = dollar_expr
                transformer = None

        if c_arg_expr is not None:
            c_arg_expr = self._DOLLAR_RE.sub('$i', c_arg_expr)

        if return_expr is not None:
            if transformer is None:
                # just a return expr, so only $i has been declared
                return_expr = self._DOLLAR_RE.sub('$i', return_expr)
            else:
                # we have a transformer, so $o has been declared
                return_expr = self._DOLLAR_RE.sub('$o', return_expr)

        return (arg_name, {'return_expr': return_expr,
                           'transformer': transformer,
                           'c_arg_expr': c_arg_expr,
                           'temporary_type': temporary_type,
                           'initial_value': initial_value,
                           'is_nullable': is_nullable,
                           'hook': hook})

    def process(self, target):
        sig = inspect.signature(target)
        self._param_sigs = sig.parameters
        self._return_sig = sig.return_annotation
        self._positional_ind = -1

        doc_str = target.__doc__

        # find content bondaries
        input_args_start = _find_start(doc_str, 'Input Args', mandatory=True)
        output_args_start = _find_start(doc_str, 'Output Args',
            offset=input_args_start)
        success_on_start = _find_start(doc_str, 'Success On',
            offset=output_args_start or input_args_start)

        if output_args_start is not None:
            input_args_end = output_args_start - 13
        elif success_on_start is not None:
            input_args_end = success_on_start - 12
        else:
            input_args_end = len(doc_str) + 1

        if success_on_start is not None:
            output_args_end = success_on_start - 12
        else:
            output_args_end = len(doc_str) + 1

        # process input args
        input_args_raw = doc_str[input_args_start:input_args_end]
        input_args_lines = [line.strip() for line
                            in input_args_raw.splitlines()
                            if line and not line.isspace()]

        arg_docs = {}
        input_args = collections.OrderedDict()
        last_arg = None
        for line in input_args_lines:
            info = self._process_input_line(line)
            if info[0]:  # was just doc
                if last_arg is not None:
                    arg_docs[last_arg] += info[1]

            else:  # had content and doc
                was_doc, doc, arg_name, arg_spec = info
                input_args[arg_name] = arg_spec
                last_arg = arg_name
                arg_docs[arg_name] = doc or ''

        # process output args
        output_args = collections.OrderedDict()
        if output_args_start is not None:
            output_args_raw = doc_str[output_args_start:output_args_end]
            output_args_lines = [line.strip() for line
                                 in output_args_raw.splitlines()
                                 if line and not line.isspace()]

            for line in output_args_lines:
                arg_name, arg_spec = self._process_output_line(line)
                output_args[arg_name] = arg_spec

        if success_on_start is not None:
            success_on = [line.strip() for line
                          in doc_str[success_on_start:].splitlines()
                          if line and not line.isspace()]
        else:
            success_on = ['GSS_S_COMPLETE']

        return ProcessorResult(
            input_args, arg_docs, output_args, success_on,
            doc_str[:input_args_start - 12])
