#! /usr/bin/perl -w
#
# File:		modules/LdapServerAccess.pm
# Package:      Low-level LDAP configuration (agent, etc.)
# Summary:	Access to some routines of yast2-ldap-server module
#
# $Id$
#
# Module provides access to LDAP server schemas. The work with schemas
# is done using functions from yast2-ldap-server module. This module
# will be installed if it is not present yet.
#

package LdapServerAccess;

use strict;
use YaST::YCP qw(:LOGGING Boolean);
use YaPI;

our %TYPEINFO;

my $package_name = "yast2-ldap-server";

YaST::YCP::Import ("Mode");
YaST::YCP::Import ("Package");

# Check if yast package for LDAP server configuration is present;
# if not, install it now.
# Return value is success
BEGIN {$TYPEINFO{InstallLdapServer} = ["function", "boolean"];}
sub InstallLdapServer {
    my $self = shift;

    if (Package->Installed ($package_name))
    {
	return 1;
    }
    if (! Package->Available ($package_name))
    {
	y2error ("Package $package_name is not available");
	return 0;
    }
    return Package->Install ($package_name);
}

# Add given schemas to the list of current LDAP server schemas
# 1st parameter: list of whole paths to schema files which should be added
BEGIN {$TYPEINFO{AddLdapSchemas} = ["function",
    "boolean",
    ["list","string"]];
}
sub AddLdapSchemas {

    my $self		= shift;
    my $new_schemas_ref = shift;
    my $restart		= shift;

    my @new_schemas	= @{$new_schemas_ref || []};
    if (Mode->config ())
    {
	return Boolean (1);
    }

    if (! $self->InstallLdapServer ())
    {
	y2error ("Cannot install $package_name, not checking LDAP schemas");
	return Boolean (0);
    }

    require YaPI::LdapServer;
    my $schema_added = 0;
    my $schemas_ref = YaPI::LdapServer->ReadSchemaIncludeList ();
    if (! defined ($schemas_ref) || ref ($schemas_ref) ne "ARRAY")
    {
	y2error ("Retrieving current LDAP schemas failed");
	return Boolean (0);
    }
    my @schemas = @{$schemas_ref};
    foreach my $schema (@new_schemas) {
	my @current_schema = grep /$schema/, @schemas;
	if (0 == scalar (@current_schema))
	{
	    y2milestone ("Including schema $schema");
	    push @schemas, $schema;
	    $schema_added = 1;
	}
	else
	{
	    y2milestone ("Schema $schema is already included");
	}
    }
    my $ret = 1;
    if ($schema_added)
    {
	$ret = YaPI::LdapServer->WriteSchemaIncludeList (\@schemas);
	$ret = $ret && YaPI::LdapServer->SwitchService(1);
    }
    return Boolean ($ret);
}

42;
# EOF
