#
# Makefile.am for .../agent-ldap/src
#

AM_CXXFLAGS = -DY2LOG=\"agent-ldap\" -Wall -I/usr/include/YaST2

plugin_LTLIBRARIES = libpy2ag_ldap.la
noinst_LTLIBRARIES = liby2ag_ldap.la

liby2ag_ldap_la_SOURCES =				\
	LdapAgent.cc					\
	LdapAgent.h
liby2ag_ldap_la_LDFLAGS = -version-info 2:0
liby2ag_ldap_la_LIBADD = @AGENT_LIBADD@ -lldapcpp -L$(libdir) 

libpy2ag_ldap_la_SOURCES =				\
        $(liby2ag_ldap_la_SOURCES)			\
        Y2CCLdapAgent.cc         #Y2CCLdapAgent.h
libpy2ag_ldap_la_LDFLAGS = -version-info 2:0
libpy2ag_ldap_la_LIBADD = @AGENT_LIBADD@ -lldapcpp -L$(libdir) 

INCLUDES = -I$(includedir)


# ----------- temporary handle also perl/ycp files:

module_DATA =		\
  LdapServerAccess.pm \
  LdapPopup.rb  \
  Ldap.rb

client_DATA = \
  ldap_browser.rb \
  ldap_config.rb

ynclude_DATA = \
  routines.rb \
  ui.rb

EXTRA_DIST = $(module_DATA) $(client_DATA) $(ynclude_DATA)

