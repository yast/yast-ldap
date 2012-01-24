#! /usr/bin/perl -w
# ------------------------------------------------------------------------------
# Copyright (c) 2006-2012 Novell, Inc. All Rights Reserved.
#
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of version 2 of the GNU General Public License as published by the
# Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, contact Novell, Inc.
#
# To contact Novell about this file by physical or electronic mail, you may find
# current contact information at www.novell.com.
# ------------------------------------------------------------------------------
#/

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
    if ( ! YaPI::LdapServer->Init() )
    {
	y2error ("Initialzing LDAP Server YaPI failed");
	return undef;
    }

    my $schema_added = 0;
    my $schemas_ref = YaPI::LdapServer->ReadSchemaList ();
    if (! defined ($schemas_ref) || ref ($schemas_ref) ne "ARRAY")
    {
	y2error ("Retrieving current LDAP schemas failed");
	return undef;
    }
    my @schemas = @{$schemas_ref};
    foreach my $schema (@new_schemas) {
        $schema =~ /^.*\/(.*)\.(schema|ldif)$/;
        my $schema_base = $1;
        y2milestone("Schemabase: $schema_base");
	my @current_schema = grep /$schema_base/, @schemas;
	if (0 == scalar (@current_schema))
	{
	    y2milestone ("Including schema $schema");
	    if (! YaPI::LdapServer->AddSchema( $schema) ) {
	        return undef;
            }
	}
	else
	{
	    y2milestone ("Schema $schema is already included");
	}
    }
    return Boolean(1);
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
    my @param		= split(/,/, $new_index->{"param"});

    if (! $self->InstallLdapServer ()) {
	y2error ("Cannot install $package_name, not checking LDAP schemas");
	return undef;
    }

    require YaPI::LdapServer;
    if ( ! YaPI::LdapServer->Init() )
    {
	y2error ("Initialzing LDAP Server YaPI failed");
	return undef;
    }
    my $indices		= YaPI::LdapServer->ReadIndex ($suffix);
    my $index_mod       = { "name" => $attr,
                            "eq"   => 0,
                            "sub"  => 0,
                            "pres" => 0
                          };

    if (defined $indices && ref ($indices) eq "HASH") {

        if ( defined $indices->{$attr} )
        {
            if (! defined $indices->{$attr}->{'eq'} )
            {
                 $indices->{$attr}->{'eq'} = 0;
            }
            if (! defined $indices->{$attr}->{'sub'} )
            {
                 $indices->{$attr}->{'sub'} = 0;
            }
            if (! defined $indices->{$attr}->{'pres'} )
            {
                 $indices->{$attr}->{'pres'} = 0;
            }

            if ( ( grep /^eq$/, @param ) || ( $indices->{$attr}->{'eq'} ) )
            {
                $index_mod->{'eq'} = 1;
            }
            if ( ( grep /^sub$/, @param ) || ( $indices->{$attr}->{'sub'} ) )
            {
                $index_mod->{'sub'} = 1;
            }
            if ( ( grep /^pres$/, @param ) || ( $indices->{$attr}->{'pres'} ) )
            {
                $index_mod->{'pres'} = 1;
            }

            if ( ( $index_mod->{'pres'} == $indices->{$attr}->{'pres'} ) &&
                 ( $index_mod->{'sub'} == $indices->{$attr}->{'sub'} ) &&
                 ( $index_mod->{'eq'} == $indices->{$attr}->{'eq'} ) )
            {
		y2milestone ("index for $attr already present");
                $present = 1;
            }
        }
        else
        {
            if ( grep /^eq$/, @param )
            {
                $index_mod->{'eq'} = 1;
            }
            if ( grep /^sub$/, @param )
            {
                $index_mod->{'sub'} = 1;
            }
            if ( grep /^pres$/, @param )
            {
                $index_mod->{'pres'} = 1;
            }
            $present = 0;
        }
        
	
	if (! $present) {
	    y2milestone ("$attr index missing, adding");
	    if (!YaPI::LdapServer->EditIndex ($suffix, $index_mod)) {
		return undef;
	    }
	}
	return Boolean(1);
    }
    return undef;
}

# adapt LDAP server ACL: allow administrator access, but deny everyone else
# 1. param: DN which should have write access
# 2. param: base DN of the database
# return value: was anyting modified? (boolean) or undef on error
BEGIN {$TYPEINFO{AddSambaACLHack} = ["function",
    "boolean",
    "string", "boolean"]
}

sub AddSambaACL {

    my $self		= shift;
    my $dn		= shift;
    my $suffix		= shift;

    if (Mode->config ()) {
	return Boolean (1);
    }

    if (! $self->InstallLdapServer ()) {
	y2error ("Cannot install $package_name, not checking LDAP schemas");
	return undef;
    }

    require YaPI::LdapServer;
    my $aclList = YaPI::LdapServer->ReadAcl($suffix);
    
    #
    # Check if there are already acl in place for the samba attributes
    # 
    foreach my $acl (@{$aclList})
    {
        if ( defined ( $acl->{'target'}->{'attrs'} ) )
        {
            my @attr = split /,/, $acl->{'target'}->{'attrs'};
            if ( ( grep { lc($_) eq "sambalmpassword" } @attr ) ||
                 ( grep { lc($_) eq "sambantpassword" } @attr ) )
            {
                y2milestone("Samba ACLs already present");
                return Boolean(0);
            }
        }
    }

    my @newAcl = (
            {
                'target' => {
                        'attrs' => 'sambaLMPassword,sambaNTPassword',
                        'dn' => {
                                'style' => 'subtree',
                                'value' => $suffix
                            }
                    },
                'access' => [
                        {
                            'level' => 'write',
                            'type' => 'dn.base',
                            'value' => $dn
                        },
                        {
                            'level' => 'none',
                            'type' => '*',
                        },
                    ]
            }
        );
    push @newAcl,(@$aclList);

    if ( ! YaPI::LdapServer->WriteAcl($suffix, \@newAcl ) )
    {
	return undef;
    }
    return Boolean(1);
}

42;
# EOF
