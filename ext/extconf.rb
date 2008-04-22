require 'mkmf'

extension_name = 'krb5_auth'
dir_config(extension_name)
have_library("c", "main")
have_library("krb5","krb5_init_context")
create_makefile('ruby_krb5_auth')
