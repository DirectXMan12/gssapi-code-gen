import inspect

from gssapi_bindings_gen.languages.base import CodeLookup, BaseHook
from gssapi_bindings_gen.languages.base import CodeGenerator, replace_vars
from gssapi_bindings_gen.utils import NotNone

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


class CythonTransformers(object):
    def default(self, def_val, otherwise):
        if isinstance(otherwise, str):
            otherwise = ['$o = %s' % otherwise]

        #if explict_branch in ('True', 'explicit'):
        #    return ([
        #        '$typedecl',
        #        'if $i is None:',
        #        '    $o = %s' % def_val,
        #        'else:',
        #        '    $o = %s' % otherwise
        #    ], '$o', None)
        #else:
        return ([
            '$typedecl = %s' % def_val,
            'if $i is not None:'] + ['    ' + line for line in otherwise],
        '$o', None)

    def bytes_to_buffer(self, input_expr, nullable=False):
        if nullable:
            return ([
                'cdef gss_buffer_desc $o = gss_buffer_desc(0, NULL)',
                'if $i is not None:',
                '    $o.length = len(%s)' % input_expr,
                '    $o.value = %s' % input_expr
            ], '&$o', None)
        else:
            return ([
                'cdef gss_buffer_desc $o = gss_buffer_desc(len({0}), {0})'.format(input_expr)
            ], '&$o', None)

    def default_assign(self, def_val):
        return ([
            'if $i is None:',
            '    $i = %s' % def_val
        ], '$i', None)


class CythonInverseTransformers(object):
    def buffer_to_bytes(self, input_expr):
        return ([
            '$o = $i.value[:$i.length]',
            'cdef OM_uint32 min_stat_$i',
            'gss_release_buffer(&min_stat_$i, $i)'
        ], '$o')


class CythonLookup(CodeLookup):
    # default output_initval: PYTHON_NAME()
    # default output_initializer: cdef PYTHON_NAME $o = $initval
    # default output_transformer: None
    # default return_expression: $o

    HOOKS = {'output_token': OutputTokenHook}
    TYPES = {
        'Name': {
            'c_type': 'gss_name_t',
            'input_transformer': 'inplace($.raw_name)',
            'output_transformer': ['$o.raw_name = $i']
        },
        'Creds': {
            'c_type': 'gss_cred_id_t',
            'input_transformer': 'inplace($.raw_cred)',
            'output_transformer': ['$o.raw_cred = $i']
        },
        'ChannelBindings': {
            'c_type': 'gss_channel_bindings_t',
            'input_transformer': ('default(GSS_C_NO_CHANNEL_BINDINGS; '
                                  '$.__cvalue__()); '
                                  'cleanup(free_non_default)'),
        },
        'SecurityContext': {
            'c_type': 'gss_ctx_id_t',
            'input_transformer': 'inplace($.raw_ctx)',
            'output_transformer': ['$o.raw_ctx = $i']
        },
        'OID': {
            'c_type': 'gss_OID',
            'input_transformer': 'inplace(&$.raw_oid)',
            'output_transformer': ['$o.raw_oid = $i[0]'],
        },
        'bytes': {
            'c_type': 'gss_buffer_desc',
            'input_transformer': 'bytes_to_buffer($)',
            'output_initval': None,
            'output_transformer': 'buffer_to_bytes($)'
        }
    }
    INVERSE_TYPES = {type_info['c_type']: type_name for
                     type_name, type_info in TYPES.items()}

    TRANSFORMERS = CythonTransformers()
    INVERSE_TRANSFORMERS = CythonInverseTransformers()
    CLEANUP_EXPRS = {
        'free_non_default': ['if $i is not None:', '    free($o)'],
        'free_buffer': ['cdef OM_uint32 min_stat_$i',
                        'gss_release_buffer(&min_stat_$i, $i)']
    }

    def is_known_type(self, python_type):
        return python_type in self.TYPES

    def as_c_type(self, python_type):
        return self.TYPES[python_type]['c_type']

    def transformer_for_type(self, python_type):
        return self.TYPES[python_type]['input_transformer']

    def inverse_transformer_for_type(self, c_type):
        python_type = self.INVERSE_TYPES[c_type]
        info = self.TYPES[python_type]

        initval = info.get('output_initval', '%s()' % python_type)
        initializer = info.get('output_initializer',
                               'cdef %s $o = $initval' % python_type)
        return_expr = info.get('return_expression', '$o')
        transformer = info.get('output_transformer')
        return ((initval, initializer, transformer), return_expr)

    def _get_transformer(self, func_name):
        return getattr(self.TRANSFORMERS, func_name)

    def transformer(self, func_name, *args, **kwargs):
        # (transformer, c_arg_expr, cleanup)
        return self._get_transformer(func_name)(*args, **kwargs)

    def make_transformer_args(self, func_name, args, param_type, can_be_none):
        argspec = inspect.getfullargspec(self._get_transformer(func_name))

        if 'nullable' in argspec.args:
            kwargs = {'nullable': can_be_none}
        else:
            kwargs = {}

        info = self.TYPES.get(param_type)
        if not info or not info['input_transformer'].startswith('inplace('):
            return (args, kwargs)

        transformer_expr = info['input_transformer'][8:-1]


        if argspec.varargs is not None:
            return (args, kwargs)

        # we want to compare against len(args) - 1 b/c args[0] == 'self'
        if len(argspec.args) - len(argspec.defaults or []) - 1 > len(args):
            return (args + [transformer_expr], kwargs)
        else:
            return (args, kwargs)

    def has_transformer(self, func_name):
        return hasattr(self.TRANSFORMERS, func_name)

    def inverse_transformer(self, func_name, *args):
        # (transformer, return_expr)
        return getattr(self.INVERSE_TRANSFORMERS, func_name)(*args)

    def has_inverse_transformer(self, func_name):
        return hasattr(self.INVERSE_TRANSFORMERS, func_name)

    def cleanup_expression(self, cleanup_type):
        return self.CLEANUP_EXPRS[cleanup_type]

    def hook(self, hook_name, arg_name):
        return self.HOOKS[hook_name](arg_name)


class CythonCodeGenerator(CodeGenerator):
    LOOKUP_CLS = CythonLookup

    def _input_argspec_to_code(self, argname, argspec):
        transformer = argspec['transformer']
        c_arg_expr = argspec['c_arg_expr']

        output_name = 'raw_%s' % argname
        arg_replacements = {'i': argname, 'o': output_name}
        if transformer is not None:
            type_decl = 'cdef %s %s' % (argspec['temporary_type'], output_name)

            transformer = replace_vars(transformer, typedecl=type_decl,
                                       **arg_replacements)

        c_arg_expr = replace_vars(c_arg_expr, **arg_replacements)

        cleanup_code = argspec['cleanup']
        if cleanup_code is not None:
            cleanup_code = replace_vars(cleanup_code, **arg_replacements)

        return (transformer, c_arg_expr, cleanup_code)

    def _output_argspec_to_code(self, argname, argspec):
        if argspec['hook'] is not None:
            return (None, None, None, None, None, argspec['hook'])
        else:
            prep_lines = []
            if not isinstance(argname, str):
                # purely computed output arg
                return (None, None, None, None, argspec['return_expr'], None)
            else:
                # normal output arg
                input_name = 'raw_%s' % argname
                c_arg_expr = argspec['c_arg_expr']
                if argspec['temporary_type'] is not None:
                    if 'optional' in argspec['tags']:
                        prep_lines.extend([
                            'cdef %s %s' % (argspec['temporary_type'], input_name),
                            'cdef %s *%s_ptr = NULL' % (argspec['temporary_type'], input_name),
                            'if %s:' % argname,
                            '    %s_ptr = &%s' % (input_name, input_name),
                            ''
                        ])
                    else:
                        prep_line = 'cdef %s %s' % (argspec['temporary_type'], input_name)
                        if argspec['initial_value'] is not None:
                            prep_line += ' = %s' % argspec['initial_value']

                        prep_lines.append(prep_line)

                if c_arg_expr is not None:
                    c_arg_expr = replace_vars(c_arg_expr, i=input_name)

                output_name = argname

                return_expr = replace_vars(argspec['return_expr'],
                                           o=output_name, i=input_name)

                null_conditions = []
                if 'optional' in argspec['tags']:
                    null_conditions.append(argname)

                if 'nullable' in argspec['tags']:
                    null_conditions.append('$i is not NULL')

                if argspec['transformer'] is not None:
                    base_initval, initializer, transformer = argspec['transformer']

                    if 'nullable' in argspec['tags'] or 'optional' in argspec['tags']:
                        initval = 'None'
                    else:
                        initval = base_initval

                    if 'optional' in argspec['tags']:
                        # with output args tagged 'optional', a func parameter
                        # with the same name specifies whether or not the method
                        # should be fetched
                        output_name = 'output_%s' % argname

                    if initializer is not None:
                        initializer = replace_vars(initializer,
                                                   initval=initval,
                                                   o=output_name, i=input_name)

                    if transformer is not None:
                        transformer_indented = ['    ' + line for
                                                line in transformer]

                        if null_conditions:
                            transformer = [
                                'if %s:' % ' and '.join(null_conditions),
                                '    $o = %s' % base_initval
                            ] + transformer_indented

                        transformer = replace_vars(transformer, o=output_name,
                                                   i=input_name)
                elif null_conditions:
                    if 'optional' in argspec['tags']:
                        output_name = 'output_%s' % argname

                    # tagged arguments require a transformer
                    transformer = replace_vars([
                        '$o = None',
                        'if %s:' % ' and '.join(null_conditions),
                        '   $o = %s' % return_expr
                    ], o=output_name, i=input_name)
                    initializer = None
                    return_expr = output_name

                else:
                    initializer = None
                    transformer = None

                return (prep_lines, c_arg_expr, initializer,
                        transformer, return_expr, None)

    def code_lines(self, target_func, argspecs):
        code_lines = []
        c_func_args = []
        cleanup_lines = []

        for argname, argspec in argspecs.input_args.items():
            transformer_code, c_arg_code, cleanup_code = (
                self._input_argspec_to_code(argname, argspec))

            if transformer_code is not None:
                code_lines.append('')
                code_lines.append('# convert %s to a C value' % argname)
                code_lines.extend(transformer_code)

            if cleanup_code is not None:
                cleanup_lines.append('')
                cleanup_lines.extend(cleanup_code)

            c_func_args.append(c_arg_code)

        initializer_lines = []
        success_lines = []
        return_args = []
        error_args = []

        code_lines.append('')

        for argname, argspec in argspecs.output_args.items():
            (prep_code, c_arg_code, initializer_code,
             success_code, return_code, hook) =  self._output_argspec_to_code(
                argname, argspec)

            if hook is not None:
                prep_code = hook.before_call()

                after_lines = hook.after_call()
                if after_lines is not None:
                    initializer_lines.extend(after_lines)

                initializer_code = None

                c_arg_code = hook.for_call()
                success_code, return_code = hook.for_success()

                err_args = hook.for_error()
                if err_args is not None:
                    error_args.extend(err_args)

            if prep_code is not None:
                code_lines.extend(prep_code)

            if initializer_code is not None:
                initializer_lines.append(initializer_code)

            if success_code is not None:
                success_lines.extend(success_code)
                success_lines.append('')

            if c_arg_code is not None:
                c_func_args.append(c_arg_code)

            return_args.append(return_code)

        code_lines.append('')
        code_lines.append('cdef OM_uint32 maj_stat, min_stat')

        code_lines.append('')
        # TODO(directxman12): support for not using nogil
        code_lines.append('with nogil:')

        func_line = '    maj_stat = gss_%s(&min_stat, %s)' % (
            target_func.__name__, ', '.join(c_func_args))

        code_lines.append(func_line)
        code_lines.append('')

        if cleanup_lines:
            code_lines.extend(cleanup_lines)

        if initializer_lines:
            code_lines.append('')
            code_lines.extend(initializer_lines)

        sig = inspect.signature(target_func)
        if isinstance(sig.return_annotation, str):
            return_line = '    return %s(%s)' % (sig.return_annotation,
                                                 ', '.join(return_args))
        elif sig.return_annotation is not inspect.Signature.empty:
            return_line = '    return %s' % return_args[0]
        else:
            return_line = None

        success_on = argspecs.success_on
        if return_line is not None:
            if len(success_on) == 1:
                code_lines.append('if maj_stat == %s:' % success_on[0])
            else:
                code_lines.append('if maj_stat in (%s):' % ', '.join(success_on))

            code_lines.extend(['    ' + line for line in success_lines])
            if code_lines:
                code_lines.extend('')

            code_lines.append(return_line)

            code_lines.append('else:')
        else:
            if len(success_on) == 1:
                code_lines.append('if maj_stat != %s:' % success_on[0])
            else:
                code_lines.append('if maj_stat not in (%s):' % ', '.join(success_on))

        code_lines.append('    raise GSSError(maj_stat, min_stat%s)' % (
            ', '.join([''] + error_args)))

        return code_lines

    def generate_func_line(self, target_func):
        sig = inspect.signature(target_func)

        param_parts = []
        for param_name, param in sig.parameters.items():
            # TODO(directxman12): deal with kw-only args, variadic args, etc
            if param.annotation is not inspect.Parameter.empty:
                if isinstance(param.annotation, NotNone):
                    param_part = '%s %s not None'
                    param_type = param.annotation.type
                else:
                    param_type = param.annotation
                    param_part = '%s %s'

                if isinstance(param_type, type):
                    param_part = param_part % (param_type.__name__, param_name)
                else:
                    param_part = param_part % (param_type, param_name)
            else:
                param_part = param_name

            if param.default is not inspect.Parameter.empty:
                param_part += '=%s' % repr(param.default)

            param_parts.append(param_part)

        return 'def %s(%s):' % (target_func.__name__, ', '.join(param_parts))

    def wrap_doc_lines(self, lines):
        return ['"""' + lines[0]] + lines[1:] + ['"""']

    def preamble(self):
        return '# gssapi-gen-code:begin\n\n\n'

    def postamble(self):
        return '$ gssapi-gen-code:end\n'
