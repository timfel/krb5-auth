require 'rubygems'

SPEC = Gem::Specification.new do |s|
  s.name                = %q{krb5-auth}
  s.version             = "0.5"
  s.author              = %q{Chris Lalancette}
  s.email               = %q{clalance@redhat.com}
  s.platform            = Gem::Platform::RUBY
  s.summary             = %q{Kerberos binding for Ruby}
  s.files               = ["README","lib/krb5-auth.rb","bin/example.rb","ext/extconf.rb","ext/ruby_krb5_auth.c","COPYING","TODO"]
  s.autorequire         = %q{Krb5Auth}
  s.has_rdoc            = true
  s.extensions		= %q{ext/extconf.rb}
end
