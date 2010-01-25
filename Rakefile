# -*- ruby -*-
# Rakefile: build ruby kerberos bindings
#
# Copyright (C) 2008 Red Hat, Inc.
#
# Distributed under the GNU Lesser General Public License v2.1 or later.
# See COPYING for details
#
# Chris Lalancette <clalance@redhat.com>

# Rakefile for ruby-rpm -*- ruby -*-
require 'rake/clean'
require 'rake/rdoctask'
require 'rake/testtask'
require 'rake/gempackagetask'

PKG_NAME='timfel-krb5-auth'
PKG_VERSION='0.8.1'

EXT_CONF='ext/extconf.rb'
MAKEFILE='ext/Makefile'
KRB5AUTH_MODULE='ext/krb5_auth.so'
SPEC_FILE='rubygem-krb5-auth.spec'
KRB5AUTH_SRC='ext/ruby_krb5_auth.c'

CLEAN.include [ "ext/*.o", KRB5AUTH_MODULE ]
CLOBBER.include [ "ext/mkmf.log", MAKEFILE ]

#
# Build locally
#
file MAKEFILE => EXT_CONF do |t|
  Dir::chdir(File::dirname(EXT_CONF)) do
    unless sh "ruby #{File::basename(EXT_CONF)}"
      $stderr.puts "Failed to run extconf"
      break
    end
  end
end
file KRB5AUTH_MODULE => [ MAKEFILE, KRB5AUTH_SRC ] do |t|
  Dir::chdir(File::dirname(EXT_CONF)) do
    unless sh "make"
      $stderr.puts "make failed"
      break
    end
  end
end
desc "Build the native library"
task :build => KRB5AUTH_MODULE

Rake::RDocTask.new(:rdoc) do |rd|
  rd.rdoc_dir = "doc"
  rd.rdoc_files.include("ext/*.c")
end

#
# Package tasks
#

PKG_FILES = FileList[
  "README",
  "examples/example.rb",
  "ext/extconf.rb",
  "ext/ruby_krb5_auth.c",
  "Rakefile"
]

SPEC = Gem::Specification.new do |s|
  s.name          = PKG_NAME
  s.version       = PKG_VERSION
  s.email         = "clalance@redhat.com"
  s.homepage      = "http://rubyforge.org/projects/krb5-auth/"
  s.summary       = "Kerberos binding for Ruby"
  s.license       = "LGPL"
  s.files         = PKG_FILES
  s.autorequire   = "Krb5Auth"
  s.require_paths = [ "ext" ]
  s.extensions    = "ext/extconf.rb"
  s.author        = "Chris Lalancette"
  s.platform      = Gem::Platform::RUBY
  s.has_rdoc      = true
end

Rake::GemPackageTask.new(SPEC) do |pkg|
    pkg.need_tar = true
    pkg.need_zip = true
end

desc "Build (S)RPM for #{PKG_NAME}"
task :rpm => [ :package ] do |t|
    system("sed -e 's/@VERSION@/#{PKG_VERSION}/' #{SPEC_FILE} > pkg/#{SPEC_FILE}")
    Dir::chdir("pkg") do |dir|
        dir = File::expand_path(".")
        system("rpmbuild --define '_topdir #{dir}' --define '_sourcedir #{dir}' --define '_srcrpmdir #{dir}' --define '_rpmdir #{dir}' --define '_builddir #{dir}' -ba #{SPEC_FILE} > rpmbuild.log 2>&1")
        if $? != 0
            raise "rpmbuild failed"
        end
    end
end

#
# Default
#

desc "Default task: build all"
task :default => [ :build, :rdoc, :rpm ] do |t|
end

Rake::TestTask.new(:test) do |test|
  task :test => [:build]
  test.libs << 'ext'
  test.warning = true
  test.verbose = true
end
