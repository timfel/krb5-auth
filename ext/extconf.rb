require 'mkmf'

RbConfig::MAKEFILE_CONFIG['CC'] = ENV['CC'] if ENV['CC']
extension_name = 'krb5_auth'
dir_config(extension_name)
have_library("c", "main")
have_library("krb5","krb5_init_context")
have_library("com_err","error_message")
create_makefile('krb5_auth')
