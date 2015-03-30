# general rules for input args:
# known wrapper types that are 'not None' can just use the form:
#   input_name
#
# known wrapper types that can be None use the form
#   input_name -> [C type] default(DEFAULT_VALUE)
#
# non-wrapper types use the form (where $-expression is explained below):
#   input_name -> [C type] $-expression
#
# $-expressions represent some substitution. $ refers to the
# name of the input param.
#
# Additionally, $-expressions may used with special "functions" in the following form:
#   input_name -> [C type] func_name($-expression; $-expression; ...)
#
# Finally, two special clauses are available, 'inplace' and 'cleanup'.  They may only
# be used when a function is the main expression.  Neither are required, and one may
# be used without the other, but if both are present they must be in the order shown:
#   input_name -> [C type] some_func(arg1; arg2); inplace($-expression); cleanup(func_name)
#   input_name -> [C type] inplace($-expression)
#
# The 'cleanup' clause indicates that additional action should be done after the call to the
# C function is made.  It may be passed the name of special expression with cleanup code.
# Note that 'cleanup' may only be used with a function
#
# When the 'inplace' clause is used as the main expression, it indicates that a temporary
# variable should not be used, and that the given $-expression used directly as the
# argument to the C function.  In this case, '$' represents the input name.
#
# When the 'inplace' clause is used with a function as the main expression, it indicates
# how the output name should be passed to the C function.  Some functions specify a base
# inplace value, which replace $ in the given $-expression.

# general rules for output args:
# use the form
#   c_param_name [C type; $-expression] -> $-expression
#
# When a function outputs a tuple, list the arguments in order of the tuple
#
# If an input argument is also an output argument, the type expression,
#   [C type; $-expression]
# should be skipped.
#
# If an output argument needs an initialization value before being passed to the C
# function, use the type expression form
#   [C type; INITIAL_VALUE; $-expression]
#
# Additionally, when the type is a known wrapper type, second $-expression may be
# skipped.
#
# In both cases above, the first $-expression represents how the argument should
# passed to the C function, while the second $-expression represents how to transform
# the C value into the python value.  For complex $ expressions, a python function may
# be used in the same was as for input args
#
# Finally, there exists a special form
#   ; -> literal expression
# which causes the literal expression to be inserted as the appropriate tuple item

# Not yet implemented/on hold
#  If an if statement is desired, use the form
#   value => $-expression; ...; otherwise-$-expression


from gssapi_bindings_gen.utils import NotNone


def init_sec_context(target_name: NotNone('Name'), creds: 'Creds' = None,
                     context: 'SecurityContext' = None, mech: 'OID' = None,
                     flags=None, lifetime=None,
                     channel_bindings: 'ChannelBindings' = None,
                     input_token: 'bytes' = None) -> 'InitSecContextResult':
    """
    Initiate a GSSAPI Security Context.

    This method initiates a GSSAPI security context, targeting the given
    target name.  To create a basic context, just provide the target name.
    Further calls used to update the context should pass in the output context
    of the last call, as well as the input token received from the acceptor.

    Warning:
        This changes the input context!

    Raises:
        InvalidTokenError
        InvalidCredentialsError
        MissingCredentialsError
        ExpiredCredentialsError
        BadChannelBindingsError
        BadMICError
        ExpiredTokenError
        DuplicateTokenError
        MissingContextError
        BadNameTypeError
        BadNameError
        BadMechanismError

    Input Args:
        creds -> [gss_cred_id_t] default(GSS_C_NO_CREDENTIAL)
            # the credenitals to use to initiate the context, or None to use the default credentials
        context -> [SecurityContext] default_assign(SecurityContext()); inplace(&$.raw_ctx)
            # the security context to update, or None to create a new context
        target_name  # the target for the security context
        mech -> [gss_OID] default(GSS_C_NO_OID; &$.raw_oid)
            # the mechanism type for this security context, or not for the default mechanism type
        flags -> [OM_uint32] default(BLAH; IntEnumFlagSet(RequirementFlag, $))
            # an iterable or int of RequirementFlags to request for the security context, or None to use mutual auth and out-of-sequence detection
        lifetime -> [OM_uint32] py_ttl_to_c($)
            # the request lifetime of the security context (0 or None mean indefinite)
        channel_bindings
            # the channel bindings (or None for no channel bindings)
        input_token
            # the token to use to update the security context, or None if creating a new context

    Output Args:
        context
        actual_mech_type [gss_OID; &$]
        ret_flags [OM_uint32; &$] -> IntEnumFlagSet(RequirementFlag, $)
        output_token -> ; hook(output_token)
        output_ttl [OM_uint32; &$] -> c_ttl_to_py($)
        ; -> maj_stat == GSS_C_CONTINUE_NEEDED

    Success On:
        GSS_S_COMPLETE
        GSS_S_CONTINUE_NEEDED
    """


def accept_sec_context(input_token: NotNone('bytes'),
                       acceptor_creds: 'Creds' = None,
                       context: 'SecurityContext' = None,
                       channel_bindings: 'ChannelBindings' = None) -> 'AcceptSecContextResult':
    """
    Accept a GSSAPI security context.

    This method accepts a GSSAPI security context using a token sent by the
    initiator, using the given credentials.  It can either be used to accept a
    security context and create a new security context object, or to update an
    existing security context object.

    Warning:
        This changes the input context!

    Raises:
        InvalidTokenError
        InvalidCredentialsError
        MissingCredentialsError
        ExpiredCredentialsError
        BadChannelBindingsError
        MissingContextError
        BadMICError
        ExpiredTokenError
        DuplicateTokenError
        BadMechanismError

    Input Args:
        context -> [SecurityContext] default_assign(SecurityContext()); inplace(&$.raw_ctx)
            # the security context to update
        acceptor_creds -> default(GSS_C_NO_CREDENTIAL)
            # the creds to use to accept the context
        input_token
            # the input token to use to update the context
        channel_bindings  # the channel bindings to use

    Output Args:
        context
        initiator_name [gss_name_t; &$]
        mech_type [nullable: gss_OID; &$]
        output_token -> ; hook(output_token)
        ret_flags [OM_uint32; &$] -> IntEnumFlagSet(RequirementFlag, $)
        output_ttl [OM_uint32; &$] -> c_ttl_to_py($)
        delegated_cred [nullable: gss_cred_id_t; &$]
        ; -> maj_stat == GSS_S_CONTINUE_NEEDED

    Success On:
        GSS_S_COMPLETE
        GSS_S_CONTINUE_NEEDED
    """


def inquire_context(context: NotNone('SecurityContext'),
                    initiator_name: bool = True, target_name: bool = True,
                    lifetime: bool = True, mech: bool = True,
                    flags: bool = True, locally_init: bool = True,
                    complete: bool = True) -> 'InquireContextResult':

    """
    Get information about a security context.

    This method obtains information about a security context, including
    the initiator and target names, as well as the TTL, mech,
    flags, and its current state (open vs closed).

    Note: the target name may be None if it would have been GSS_C_NO_NAME

    Raises:
        MissingContextError

    Input Args:
        context  # the context in question

    Output Args:
        initiator_name [optional: gss_name_t; $]
        target_name [nullable, optional: gss_name_t; $]
        lifetime [optional: OM_uint32; $] -> c_ttl_to_py($)
        mech [optional: gss_OID; $]
        flags [optional: OM_unit32; $] -> IntEnumFlagSet(RequirementFlag, $)
        locally_init [optional: bint; $] -> $
        is_complete [optional: bint; $] -> $
    """


def context_time(context: NotNone('SecurityContext')) -> int:
    """
    Get the amount of time for which the given context will remain valid.

    This method determines the amount of time for which the given
    security context will remain valid.  An expired context will
    give a result of 0.

    Raises:
        ExpiredContextError
        MissingContextError

    Input Args:
        context  # the context for which to get the time

    Output Args:
        ttl [OM_uint32; &$] -> c_ttl_to_py($)
    """


def process_context_token(context: NotNone('SecurityContext'), token: 'bytes'):
    """
    Process a token asynchronously

    This method provides a way to process a token, even if the
    given security context is not expecting one.  For example,
    if the initiator has the initSecContext return that the context
    is complete, but the acceptor is unable to accept the context,
    and wishes to send a token to the initiator, letting the
    initiator know of the error.

    Raises:
        InvalidTokenError
        MissingContextError

    Input Args:
        context  # the security context to update
        token -> bytes_to_buffer($)  # the token to use to update the context
    """
