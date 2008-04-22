# Generated from kerberos-0.4.gem by gem2rpm -*- rpm-spec -*-
%define ruby_sitelib %(ruby -rrbconfig -e "puts Config::CONFIG['sitelibdir']")
%define gemdir %(ruby -rubygems -e 'puts Gem::dir' 2>/dev/null)
%define gemname krb5-auth
%define geminstdir %{gemdir}/gems/%{gemname}-%{version}

Summary: Kerberos binding for ruby
Name: rubygem-%{gemname}
Version: 0.5
Release: 1%{?dist}
Group: Development/Languages
License: LGPLv2+
URL: http://rubyforge.org/projects/krb5-auth/%{gemname}-%{version}.gem
Source0: http://rubyforge.org/projects/krb5-auth/%{gemname}-%{version}.gem
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: rubygems
BuildRequires: rubygems
BuildRequires: krb5-devel
Provides: rubygem(%{gemname}) = %{version}

%description
Kerberos binding for ruby

%prep

%build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{gemdir}
gem install --local --install-dir %{buildroot}%{gemdir} \
            --force --rdoc %{SOURCE0}

%clean
rm -rf %{buildroot}

%files
%defattr(-, root, root, -)
%{gemdir}/gems/%{gemname}-%{version}/
%doc %{gemdir}/doc/%{gemname}-%{version}
%{gemdir}/cache/%{gemname}-%{version}.gem
%{gemdir}/specifications/%{gemname}-%{version}.gemspec


%changelog
* Tue Apr 22 2008 Chris Lalancette <clalance@redhat.com> - 0.5-1
- Move project to krb5-auth on RubyForge

* Fri Jan 11 2008 Chris Lalancette <clalance@redhat.com> - 0.4-3
- Update the destroy method to use alternate caches

* Fri Jan 11 2008 Chris Lalancette <clalance@redhat.com> - 0.4-2
- Update the cache method to use alternate caches

* Wed Jan 02 2008 Chris Lalancette <clalance@redhat.com> - 0.4-1
- Initial package

