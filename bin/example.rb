require 'kerberos'
include Kerberos

krb5 = Krb5.new

# get the default realm
default_realm = krb5.get_default_realm
puts default_realm

# Get initial credentials for the default principal and default keytab
krb5.get_init_creds_keytab

# cache those credentials in the default cache location
krb5.cache

# destroy those same credentials from the default cache location
krb5.destroy
