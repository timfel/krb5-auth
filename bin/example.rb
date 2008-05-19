require 'rubygems'
require 'krb5_auth'
include Krb5Auth

krb5 = Krb5.new

# get the default realm
default_realm = krb5.get_default_realm
puts "Default realm is: " + default_realm

# try to cache non-existant data (this should fail and throw an exception)
begin
  krb5.cache
rescue Krb5Auth::Krb5::Exception
  puts "Failed caching credentials before obtaining them.  Continuing..."
end

# Get initial credentials for the default principal and default keytab
krb5.get_init_creds_keytab

# cache those credentials in the default cache location
krb5.cache

puts "Principal: " + krb5.get_default_principal

# destroy those same credentials from the default cache location
krb5.destroy

# close the object (releases all memory)
krb5.close

# now try to use the object again; this should fail and throw an exception
begin
  krb5.cache
rescue Krb5Auth::Krb5::Exception
  puts "Tried to reuse closed object; continuing..."
end
