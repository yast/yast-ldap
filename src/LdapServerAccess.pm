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
# 2nd parameter: restart LDAP server after adding ?
# return value: was anyting modified? (boolean) or undef on error
BEGIN {$TYPEINFO{AddLdapSchemas} = ["function",
    "boolean",
    ["list","string"], "boolean"];
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
	return undef;
    }

    require YaPI::LdapServer;
    my $schema_added = 0;
    my $schemas_ref = YaPI::LdapServer->ReadSchemaIncludeList ();
    if (! defined ($schemas_ref) || ref ($schemas_ref) ne "ARRAY")
    {
	y2error ("Retrieving current LDAP schemas failed");
	return undef;
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
    if ($schema_added) {
	if (! YaPI::LdapServer->WriteSchemaIncludeList (\@schemas)) {
	    return undef;
	}
	if ($restart) {
	    YaPI::LdapServer->SwitchService (1);
	}
    }
    return Boolean ($schema_added);
}

# Add new index to ldap server database
# 1. map describing the index (see YaPI::LdapServer::AddIndex)
# 2. LDAP suffix
# 3. should be server restarted at the end?
# return value: was anyting modified? (boolean) or undef on error
BEGIN {$TYPEINFO{AddIndex} = ["function",
    "boolean",
    ["map", "string","string"], "string", "boolean"];
}
sub AddIndex {

    my $self		= shift;
    my $new_index	= shift;
    my $suffix		= shift;
    my $restart		= shift;
    my $present		= 0;

    if (Mode->config ()) {
	return Boolean (1);
    }

    if (!defined $new_index || ref ($new_index) ne "HASH" ||
	 !defined $new_index->{"attr"} || !defined $new_index->{"param"}) {
	
	y2error ("wrong or missing 'index' parameter");
	return undef;
    }

    my $attr		= $new_index->{"attr"};
    my $param		= $new_index->{"param"};

    if (! $self->InstallLdapServer ()) {
	y2error ("Cannot install $package_name, not checking LDAP schemas");
	return undef;
    }

    require YaPI::LdapServer;
    my $indices		= YaPI::LdapServer->ReadIndex ($suffix);
    if (defined $indices && ref ($indices) eq "ARRAY") {
	    
	foreach my $index (@$indices) {
	    my $attrs	= $index->{"attr"} || "";
	    my $params	= $index->{"param"} || "";

	    my @current_attrs	= grep /^$attr$/, split (/,/, $attrs);
	    my @current_params	= grep /^$param$/, split (/,/, $param);

	    if (scalar (@current_attrs) >0 && scalar (@current_params) > 0) {
		y2milestone ("index for $attr already present");
		$present	= 1;
	    }
	}
	
	if (! $present) {
	    y2milestone ("$attr index missing, adding");
	    if (!YaPI::LdapServer->AddIndex ($suffix, $new_index)) {
		return undef;
	    }
	    if ($restart) {
		YaPI::LdapServer->SwitchService(1);
	    }
	}
	return Boolean (!$present);
    }
    return undef;
}

# adapt LDAP server ACL: allow administrator access, but deny everyone else
# 1. param: administrator's DN
# 2. param: restart LDAP server?
# return value: was anyting modified? (boolean) or undef on error
BEGIN {$TYPEINFO{AddSambaACLHack} = ["function",
    "boolean",
    "string", "boolean"]
}
sub AddSambaACLHack {

    my $self		= shift;
    my $dn		= shift;
    my $restart		= shift;

    if (Mode->config ()) {
	return Boolean (1);
    }

    if (! $self->InstallLdapServer ()) {
	y2error ("Cannot install $package_name, not checking LDAP schemas");
	return undef;
    }

    require YaPI::LdapServer;

    if (!SCR->Write (".ldapserver.sambaACLHack", $dn)) {
	return undef;
    }
    if ($restart) {
	YaPI::LdapServer->SwitchService(1);
    }
    return Boolean (1);
}

42;
# EOF
