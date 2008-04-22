require 'rubygems'

SPEC = Gem::Specification.new do |s|
  s.name                = %q{kerberos}
  s.version             = "0.4"
  s.author              = %q{Chris Lalancette}
  s.email               = %q{clalance@redhat.com}
  s.platform            = Gem::Platform::RUBY
  s.summary             = %q{Kerberos binding for ruby}
  s.files               = ["README","lib/kerberos.rb","bin/example.rb","ext/extconf.rb","ext/ruby_kerberos.c","ext/ruby_kerberos.h","ext/admin.h"]
  s.autorequire         = %q{kerberos}
  s.has_rdoc            = true
  s.extensions		= %q{ext/extconf.rb}
end
