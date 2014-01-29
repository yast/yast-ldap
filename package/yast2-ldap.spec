#
# spec file for package yast2-ldap
#
# Copyright (c) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


Name:           yast2-ldap
Version:        3.1.0
Release:        0

BuildRoot:      %{_tmppath}/%{name}-%{version}-build
Source0:        %{name}-%{version}.tar.bz2

Group:          System/YaST
License:        GPL-2.0
BuildRequires:	gcc-c++ libldapcpp-devel doxygen yast2-core-devel yast2 libtool
BuildRequires:  yast2-devtools >= 3.0.6
Summary:	YaST2 - LDAP Agent
Requires: 	ldapcpplib yast2

%description
This agent is used by various YaST2 modules to work with LDAP. It
enables searching the LDAP tree and adding/deleting/modifying items on
an LDAP server.

%prep
%setup -n %{name}-%{version}

%build
%yast_build

%install
%yast_install


%files
%defattr(-,root,root)
%{yast_moduledir}/*
%{yast_clientdir}/*
%{yast_scrconfdir}/*.scr
%{yast_plugindir}/libpy2ag_ldap.so.*
%{yast_plugindir}/libpy2ag_ldap.so
%{yast_plugindir}/libpy2ag_ldap.la
%doc %{yast_docdir}
