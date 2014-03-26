# encoding: utf-8

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

# File:        modules/Ldap.ycp
# Module:        Configuration of LDAP client
# Summary:        LDAP client configuration data, I/O functions.
# Authors:        Peter Varkoly <varkoly@suse.com>
#               Thorsten Kukuk <kukuk@suse.de>
#                Anas Nashif <nashif@suse.de>
#
# $Id$
require "yast"

module Yast
  class LdapClass < Module
    def main
      Yast.import "UI"
      textdomain "ldap"

      Yast.import "FileUtils"
      Yast.import "Hostname"
      Yast.import "Label"
      Yast.import "Message"
      Yast.import "Mode"
      Yast.import "Nsswitch"
      Yast.import "Package"
      Yast.import "Pam"
      Yast.import "Popup"
      Yast.import "Progress"
      Yast.import "Report"
      Yast.import "Service"
      Yast.import "Stage"
      Yast.import "String"
      Yast.import "Summary"
      Yast.import "URL"

      # show popups with error messages?
      @use_gui = true

      # DN of base configuration object
      @base_config_dn = ""


      # Required packages for this module to operate
      # -- they are now required only when LDAP is set for authentication
      @required_packages = []

      # Write only, used during autoinstallation.
      # Don't run services and SuSEconfig, it's all done at one place.
      @write_only = false

      # Are LDAP services available via nsswitch.conf?
      @start = false

      # Is NIS service available? If yes, and LDAP client will be enabled, warn
      # user (see bug #36981)
      @nis_available = false

      # If no, automounter will not be affected.
      @_autofs_allowed = true
      # Start automounter and import the settings from LDAP
      @_start_autofs = false

      # If login of LDAP uses to local machine is enabled
      @login_enabled = true

      # which attribute have LDAP groups for list of members
      @member_attribute = ""

      # IP addresses of LDAP server.
      @server = ""

      # local settings modified?
      @modified = false

      # /etc/openldap/ldap.conf modified?
      @openldap_modified = false

      # base DN
      @base_dn = ""

      @ldap_tls = "no"

      # CA certificates for server certificate verification
      # At least one of these are required if tls_checkpeer is "yes"
      @tls_cacertdir = ""
      @tls_cacertfile = ""
      # Require and verify server certificate (yes/no)
      @tls_checkpeer = "yes"

      # Which crypt method should be used?
      @pam_password = "exop"

      # lines of /etc/passwd, starting with +/-
      @plus_lines_passwd = []

      @default_port = 389

      # If home directories of LDAP users are stored on this machine
      @file_server = true

      # are we binding anonymously?
      @anonymous = false

      # bind password for LDAP server
      @bind_pass = nil

      # DN for binding to LDAP server
      @bind_dn = ""

      # DN of currently edited configuration module
      @current_module_dn = ""
      # DN of currently edited template
      @current_template_dn = ""

      # if eDirectory is used as server
      @nds = false

      # if crypted connection was switched of after failure (#330054)
      @tls_switched_off = false

      @nds_checked = false

      # if OES is used as a client
      @oes = false

      # defaults for adding new config objects and templates
      @new_objects = {
        "suseUserConfiguration"  => {
          "suseSearchFilter"      => ["objectClass=posixAccount"],
          "susePasswordHash"      => ["SSHA"],
          "suseSkelDir"           => ["/etc/skel"],
          "suseMinUniqueId"       => ["1000"],
          "suseNextUniqueId"      => ["1000"],
          "suseMaxUniqueId"       => ["60000"],
          "suseMinPasswordLength" => ["5"],
          "suseMaxPasswordLength" => ["8"]
        },
        "suseGroupConfiguration" => {
          "suseSearchFilter" => ["objectClass=posixGroup"],
          "suseMinUniqueId"  => ["1000"],
          "suseNextUniqueId" => ["1000"],
          "suseMaxUniqueId"  => ["60000"]
        },
        "suseUserTemplate"       => {
          "objectClass"         => [
            "top",
            "suseObjectTemplate",
            "suseUserTemplate"
          ],
          "suseNamingAttribute" => ["uid"],
          "suseDefaultValue"    => [
            "homeDirectory=/home/%uid",
            "loginShell=/bin/bash"
          ],
          "susePlugin"          => ["UsersPluginLDAPAll"]
        },
        "suseGroupTemplate"      => {
          "objectClass"         => [
            "top",
            "suseObjectTemplate",
            "suseGroupTemplate"
          ],
          "suseNamingAttribute" => ["cn"],
          "susePlugin"          => ["UsersPluginLDAPAll"]
        }
      }

      @base_template_dn = @base_config_dn

      # settings saved at LDAP server modified
      @ldap_modified = false

      @config_modules = {}
      @templates = {}

      @bound = false

      # DN's of groups (posixGroups) in LDAP
      @groups_dn = []

      # Map of object classes (from schema). Indexed by names.
      @object_classes = {}

      # Map of atribute types (from schema). Indexed by names.
      @attr_types = {}

      # encryption schemes supported by slappasswd
      @hash_schemas = ["CLEAR", "CRYPT", "SHA", "SSHA", "MD5", "SMD5"]

      # Available configuration modules (objectClass names)
      # TODO update
      @available_config_modules = [
        "suseUserConfiguration",
        "suseGroupConfiguration"
      ]

      # The defualt values, which should replace the ones from Read ()
      # Used during instalation, when we want to do a reasonable proposal
      @initial_defaults = {}

      # If the default values, used from ldap-server module were used
      # to configure ldap-client
      @initial_defaults_used = false

      @schema_initialized = false

      @ldap_initialized = false

      # was LDAP connection initialized with TLS?
      @tls_when_initialized = false

      # If false, do not read settings already set from outside
      # used e.g. for Users YaPI. see bug #60898
      @read_settings = true

      # if sshd should be restarted during write phase
      @restart_sshd = false

      # if /etc/passwd was read
      @passwd_read = false

      # packages needed for pam_ldap/nss_ldap configuration
      @pam_nss_packages = ["pam_ldap", "nss_ldap"]

      # packages needed for sssd configuration
      @sssd_packages = ["sssd"]

      # if sssd is used instead of pam_ldap/nss_ldap (fate#308902)
      @sssd = true

      @ldap_error_hints = {
        # hint to error message
        -1  => _(
          "Verify that the LDAP Server is running and reachable."
        ),
        # hint to error message
        -11 => _(
          "Failed to establish TLS encryption.\nVerify that the correct CA Certificate is installed and the Server Certificate is valid."
        ),
        # hint to error message
        2   => _(
          "Failed to establish TLS encryption.\nVerify that the Server has StartTLS support enabled."
        )
      }
    end

    #----------------------------------------------------------------

    # If the base DN has changed from a nonempty one, it may only be
    # changed at boot time. Use this to warn the user.
    # @return whether changed by SetBaseDN
    def BaseDNChanged
      @base_dn_changed
    end

    # obsolete, use BaseDNChanged
    def DomainChanged
      BaseDNChanged()
    end

    # Get the Base DN
    def GetBaseDN
      @base_dn
    end

    # obsolete, use GetBaseDN
    def GetDomain
      GetBaseDN()
    end

    # Set new LDAP base DN
    # @param [String] new_base_dn a new base DN
    def SetBaseDN(new_base_dn)
      @base_dn_changed = true if @base_dn != new_base_dn
      @base_dn = new_base_dn
      nil
    end

    # obsolete, use SetBaseDN
    def SetDomain(new_domain)
      SetBaseDN(new_domain)
    end

    # Set the defualt values, which should replace the ones from Read ()
    # Used during instalation, when we want to do a reasonable proposal
    def SetDefaults(settings)
      settings = deep_copy(settings)
      Builtins.y2milestone("using initial defaults: %1", settings)
      @initial_defaults = Builtins.eval(settings)
      true
    end

    # set the value of read_settings variable
    # which means, do not read some settings from system
    def SetReadSettings(read)
      @read_settings = read
      @read_settings
    end

    # Read single entry from /etc/openldap/ldap.conf file
    # @param [String] entry entry name
    # @param [String] defvalue default value if entry is not present
    # @return entry value
    def ReadLdapConfEntry(entry, defvalue)
      value = defvalue
      ret = SCR.Read(path(".ldap_conf.v."+ entry ))
      if ret == nil
        value = defvalue
      elsif Ops.is_list?(ret)
        value = Ops.get_string(Convert.to_list(ret), 0, defvalue)
      else
        value = Builtins.sformat("%1", ret)
      end
      value
    end

    # Read multi-valued entry from /etc/openldap/ldap.conf file
    # @param [String] entry entry name
    # @return entry value
    def ReadLdapConfEntries(entry)
      ret = SCR.Read(path( ".ldap_conf.v."+ entry ))
      if ret == nil
        return []
      elsif Ops.is_list?(ret)
        return Convert.convert(ret, :from => "any", :to => "list <string>")
      else
        return [Builtins.sformat("%1", ret)]
      end
    end

    # Write (single valued) entry to /etc/openldap/ldap.conf
    # @param [String] entry name
    # @param [String] value; if value is nil, entry will be removed
    def WriteLdapConfEntry(entry, value)
      SCR.Write(path( ".ldap_conf.v." + entry ), value.nil ? nil : [value] ) 
      nil
    end

    # Write (possibly multi valued) entry to /etc/openldap/ldap.conf
    # @param [String] entry name
    # @param [Array<String>] value it is of type [attr1, attr2],
    # in /etc/openldap/ldap.conf should be written as "entry attr1 attr2"
    # @example to write "nss_map_attribute       uniquemember member", call
    # WriteLdapConfEntries ("nss_map_attribute", ["uniquemember", "member"])
    def WriteLdapConfEntries(entry, value)
      value = deep_copy(value)
      current = ReadLdapConfEntries(entry)
      values = []
      Builtins.foreach(current) do |val|
        lval = Builtins.splitstring(val, " \t")
        if Builtins.tolower(Ops.get_string(lval, 0, "")) !=
            Builtins.tolower(Ops.get(value, 0, ""))
          values = Builtins.add(values, val)
        else
          values = Builtins.add(values, Builtins.mergestring(value, " "))
        end
      end
      values = [Builtins.mergestring(value, " ")] if Builtins.size(current) == 0
      SCR.Write( path(".ldap_conf.v." + entry), values )

      nil
    end

    # Add a new value to the entry in /etc/openldap/ldap.conf
    # @param [String] entry name
    # @param [String] value
    def AddLdapConfEntry(entry, value)
      current = ReadLdapConfEntries(entry)
      current = Builtins.maplist(current) { |e| Builtins.tolower(e) }

      if !Builtins.contains(current, Builtins.tolower(value))
        SCR.Write( path(".ldap_conf.v." + entry), current | [value] )
      end

      nil
    end

    # Check if current machine runs OES
    def CheckOES
      @oes = Package.Installed("NOVLam")
      @oes
    end

    # convert list of uri's to list of hosts
    def uri2servers(uri)
      Builtins.mergestring(
        Builtins.maplist(Builtins.splitstring(uri, " \t")) do |u|
          url = URL.Parse(u)
          h = Ops.get_string(url, "host", "")
          p = Ops.get_string(url, "port", "")
          if Ops.get_string(url, "scheme","") == "ldaps"
             @ldap_tls = "yes"
          end
          if p != ""
            @ldap_tls = "yes" if( p == "636" || p == "ldaps" )
            h = "#{h}:#{p}"
          end
          h
        end,
        " "
      )
    end

    # Read values of LDAP hosts from ldap.conf
    # get them from 'uri' or 'host' values
    def ReadLdapHosts
      ret = ""
      uri = ReadLdapConfEntry("uri", "")
      if uri == ""
        ret = ReadLdapConfEntry("host", "")
      else
        ret = uri2servers(uri)
      end
      ret
    end

    # Reads LDAP settings from the SCR
    # @return success
    def Read

      @start          = Nsswitch.ReadDb("passwd").include?("sss")
      @server         = ReadLdapHosts()
      @base_dn        = ReadLdapConfEntry("BASE", "")
      @tls_cacert     = ReadLdapConfEntry("TLS_CACERT", "")
      @tls_cacertdir  = ReadLdapConfEntry("TLS_CACERTDIR", "")
      @bind_dn        = ReadLdapConfEntry("BINDDN","cn=Administrator," + @base_dn )
      @base_config_dn = "ou=ldapconfig," +@base_dn
      
      Builtins.y2milestone("Read LDAP Settings: server %1, base_dn %2, bind_dn %3, base_config_dn %4",@server, @base_dn, @bind_dn, @base_config_dn)

      true
    end

    # Dump the LDAP settings to a map based on /etc/openldap/slapd.conf
    # @return $["start":, "servers":[...], "domain":]
    def Export
      e = {
        "start_ldap"       => @start,
        "ldap_server"      => @server,
        "ldap_domain"      => @base_dn,
        "ldap_tls"         => @ldap_tls,
        "bind_dn"          => @bind_dn,
        "base_config_dn"   => @base_config_dn
      }
    end

    def FindLDAPServer
      # ask DNS for LDAP server address if none is defined
        return nil unless FileUtils.Exists("/usr/bin/dig")
        domain = Hostname.CurrentDomain
        # workaround for bug#393951
        if domain == "" && Stage.cont
          out2 = Convert.to_map(
            SCR.Execute(path(".target.bash_output"), "domainname")
          )
          if Ops.get_integer(out2, "exit", 0) == 0
            domain = Builtins.deletechars(
              Ops.get_string(out2, "stdout", ""),
              "\n"
            )
          end
        end
        out = Convert.to_map(
          SCR.Execute(
            path(".target.bash_output"),
            Builtins.sformat("dig SRV _ldap._tcp.%1 +short", domain)
          )
        )
        first = Ops.get(
          Builtins.splitstring(Ops.get_string(out, "stdout", ""), "\n"),
          0,
          ""
        )
        srv = Ops.get(Builtins.splitstring(first, " "), 3, "")
        if srv != ""
          # remove dot from the end of line
          @server = Builtins.substring(
            srv,
            0,
            Ops.subtract(Builtins.size(srv), 1)
          )
          Builtins.y2milestone("LDAP server address acquired from DNS...")
          # now, check if there is reasonable 'default' DN
          dn = ""
          Builtins.foreach(Builtins.splitstring(domain, ".")) do |part|
            dn = Ops.add(dn, ",") if dn != ""
            dn = Ops.add(Ops.add(dn, "dc="), part)
          end
          if 0 ==
              SCR.Execute(
                path(".target.bash"),
                Builtins.sformat(
                  "ldapsearch -x -h %1 -s base -b '' namingContexts | grep -i '^namingContexts: %2'",
                  @server,
                  dn
                )
              )
            Builtins.y2milestone("proposing DN %1 based on %2", dn, domain)
            @base_dn = dn
          end
        end
    end
    # ------------- functions for work with LDAP tree contents ------------

    # Error popup for errors detected during LDAP operation
    # @param [String] type error type: binding/reading/writing
    # @param detailed error message (from agent-ldap)
    def LDAPErrorMessage(type, error)
      ldap_error = {
        # error message:
        "initialize"   => _(
          "\nThe server could be down or unreachable.\n"
        ),
        # error message:
        "missing_dn"   => _(
          "\nThe value of DN is missing or invalid.\n"
        ),
        # error message:
        "at_not_found" => _("\nAttribute type not found.\n"),
        # error message:
        "oc_not_found" => _("\nObject class not found.\n")
      }

      error_type = {
        # error message, more specific description follows
        "init"   => _(
          "Connection to the LDAP server cannot be established."
        ),
        # error message, more specific description follows
        "bind"   => _(
          "A problem occurred while connecting to the LDAP server."
        ),
        # error message, more specific description follows
        "read"   => _(
          "A problem occurred while reading data from the LDAP server."
        ),
        # error message, more specific description follows
        "users"  => _(
          "A problem occurred while writing LDAP users."
        ),
        # error message, more specific description follows
        "groups" => _(
          "A problem occurred while writing LDAP groups."
        ),
        # error message, more specific description follows
        "write"  => _(
          "A problem occurred while writing data to the LDAP server."
        ),
        # error message, more specific description follows
        "schema" => _(
          "A problem occurred while reading schema from the LDAP server."
        )
      }

      if !@use_gui || Mode.commandline
        Builtins.y2error(Ops.get_string(error_type, type, "Unknown LDAP error"))
        Builtins.y2error(Ops.get_string(ldap_error, error, error))
        return
      end

      error = "YaST error?" if error == nil

      UI.OpenDialog(
        HBox(
          HSpacing(0.5),
          VBox(
            VSpacing(0.5),
            # label
            Left(Heading(Label.ErrorMsg)),
            # default error message
            Label(
              Ops.get_locale(
                error_type,
                type,
                _("An unknown LDAP error occurred.")
              )
            ),
            ReplacePoint(Id(:rp), Empty()),
            VSpacing(0.5),
            Left(
              CheckBox(
                Id(:details),
                Opt(:notify),
                # checkbox label
                _("&Show Details"),
                false
              )
            ),
            PushButton(Id(:ok), Opt(:key_F10, :default), Label.OKButton)
          ),
          HSpacing(0.5)
        )
      )
      ret = nil
      UI.ChangeWidget(Id(:details), :Enabled, false) if error == ""
      begin
        ret = UI.UserInput
        if ret == :details
          if Convert.to_boolean(UI.QueryWidget(Id(:details), :Value))
            UI.ReplaceWidget(
              Id(:rp),
              VBox(Label(Ops.get_string(ldap_error, error, error)))
            )
          else
            UI.ReplaceWidget(Id(:rp), Empty())
          end
        end
      end while ret != :ok && ret != :cancel
      UI.CloseDialog

      nil
    end

    # Reads and returns error map (=message + code) from agent
    def LDAPErrorMap
      ret = Convert.to_map(SCR.Read(path(".ldap.error")))
      if Ops.get_string(@ldap_error_hints, Ops.get_integer(ret, "code", 0), "") != ""
        Ops.set(
          ret,
          "hint",
          Ops.get_string(@ldap_error_hints, Ops.get_integer(ret, "code", 0), "")
        )
      end
      deep_copy(ret)
    end

    # Reads and returns error message from agent
    def LDAPError
      err_map = LDAPErrorMap()
      error = Ops.get_string(err_map, "msg", "")
      if Ops.get_string(err_map, "server_msg", "") != ""
        error = Builtins.sformat(
          "%1\n(%2)",
          error,
          Ops.get_string(err_map, "server_msg", "")
        )
      end
      error
    end


    # return administrator's DN
    # if it was not read yet, read it now
    def GetBindDN
      if @bind_pass == nil && Builtins.size(@bind_dn) == 0
        Builtins.y2milestone("--- bind dn not read yet or empty, reading now")
        @bind_dn = ReadLdapConfEntry("BINDDN", "")
      end
      @bind_dn
    end


    # this is a hack
    def GetFirstServer(servers)
      if @bind_pass == nil && servers == ""
        Builtins.y2milestone("--- server not read yet or empty, reading now")
        servers = ReadLdapHosts()
      end

      l_servers = Builtins.splitstring(servers, " \t")
      srv = Ops.get_string(l_servers, 0, "")
      Ops.get(Builtins.splitstring(srv, ":"), 0, "")
    end

    # this is a hack
    def GetFirstPort(servers)
      if @bind_pass == nil && servers == ""
        Builtins.y2milestone("--- server not read yet or empty, reading now")
        servers = ReadLdapHosts()
      end

      l_servers = Builtins.splitstring(servers, " \t")
      srv = Ops.get_string(l_servers, 0, "")
      return @default_port if !Builtins.issubstring(srv, ":")
      s_port = Builtins.substring(srv, Ops.add(Builtins.search(srv, ":"), 1))
      if s_port == "" || Builtins.tointeger(s_port) == nil
        return @default_port
      else
        return Builtins.tointeger(s_port)
      end
    end

    # Shut down existing LDAP connection
    def LDAPClose
      @ldap_initialized = false
      Convert.to_boolean(SCR.Execute(path(".ldap.close")))
    end

    # Initializes LDAP agent
    def LDAPInit
      # FIXME what if we have more servers? -> choose dialog?
      ret = ""
      args = {
        "hostname"   => GetFirstServer(@server),
        "port"       => GetFirstPort(@server),
        "use_tls"    => @ldap_tls,
        "cacertdir"  => @tls_cacertdir,
        "cacertfile" => @tls_cacertfile
      }
      init = Convert.to_boolean(SCR.Execute(path(".ldap"), args))
      if init == nil
        # error message
        ret = _("Unknown error. Perhaps 'yast2-ldap' is not available.")
      else
        @ldap_initialized = init
        @tls_when_initialized = ( @ldap_tls == "yes" )
        ret = LDAPError() if !init
      end
      ret
    end

    # Initializes LDAP agent; use the data passed as argument instead global values
    # Returns whole error map, not just message
    def LDAPInitArgs(args)
      args = deep_copy(args)
      ret = {}
      init = Convert.to_boolean(SCR.Execute(path(".ldap"), args))
      if init == nil
        # error message
        Ops.set(
          ret,
          "msg",
          _("Unknown error. Perhaps 'yast2-ldap' is not available.")
        )
      else
        @ldap_initialized = init
        if !init
          ret = LDAPErrorMap()
        else
          @tls_when_initialized = Ops.get_string(args, "use_tls", "") == "yes"
        end
      end
      deep_copy(ret)
    end

    # Check if LDAP connection can be established with given values.
    def CheckLDAPConnection(args)
      args = deep_copy(args)
      LDAPClose()
      errmap = LDAPInitArgs(args)

      return true if errmap == {}

      details = Ops.get_string(errmap, "msg", "")
      if Ops.get_string(errmap, "server_msg", "") != ""
        details = Builtins.sformat(
          "%1\n%2",
          details,
          Ops.get_string(errmap, "server_msg", "")
        )
      end
      hint = Ops.get_string(errmap, "hint", "")

      UI.OpenDialog(
        HBox(
          HSpacing(0.5),
          VBox(
            VSpacing(0.5),
            # label
            Left(Heading(Label.ErrorMsg)),
            # error message
            Left(
              Label(_("Connection to the LDAP server cannot be established."))
            ),
            ReplacePoint(Id(:rp), Empty()),
            VSpacing(0.2),
            Left(
              CheckBox(
                Id(:details),
                Opt(:notify),
                # checkbox label
                _("&Show Details"),
                false
              )
            ),
            VSpacing(),
            hint != "" ? VBox(Left(Label(hint)), VSpacing()) : VBox(),
            Left(
              Label(
                # question following error message (yes/no buttons follow)
                _("Really keep this configuration?")
              )
            ),
            HBox(
              PushButton(Id(:yes), Opt(:key_F10, :default), Label.YesButton),
              PushButton(Id(:no), Opt(:key_F9), Label.NoButton)
            )
          ),
          HSpacing(0.5)
        )
      )
      ret = nil
      begin
        ret = UI.UserInput
        if ret == :details
          if Convert.to_boolean(UI.QueryWidget(Id(:details), :Value))
            UI.ReplaceWidget(Id(:rp), VBox(Label(details)))
          else
            UI.ReplaceWidget(Id(:rp), Empty())
          end
        end
      end while ret != :yes && ret != :no
      UI.CloseDialog
      ret == :yes
    end

    # popup shown after failed connection: ask for retry withou TLS (see bug 246397)
    # @return true if user wants to retry without TLS
    def ConnectWithoutTLS(errmap)
      errmap = deep_copy(errmap)
      details = Ops.get_string(errmap, "msg", "")
      if Ops.get_string(errmap, "server_msg", "") != ""
        details = Builtins.sformat(
          "%1\n%2",
          details,
          Ops.get_string(errmap, "server_msg", "")
        )
      end

      UI.OpenDialog(
        HBox(
          HSpacing(0.5),
          VBox(
            VSpacing(0.5),
            # label
            Left(Heading(Label.ErrorMsg)),
            # error message
            Left(
              Label(_("Connection to the LDAP server cannot be established."))
            ),
            ReplacePoint(Id(:rp), Empty()),
            VSpacing(0.2),
            Left(
              CheckBox(
                Id(:details),
                Opt(:notify),
                # checkbox label
                _("&Show Details"),
                false
              )
            ),
            VSpacing(),
            Left(
              Label(
                # question following error message (yes/no buttons follow)
                _(
                  "A possible reason for the failed connection may be that your client is\n" +
                    "configured for TLS/SSL but the server does not support it.\n" +
                    "\n" +
                    "Retry connection without TLS/SSL?\n"
                )
              )
            ),
            ButtonBox(
              PushButton(Id(:yes), Opt(:key_F10, :default), Label.YesButton),
              PushButton(Id(:no), Opt(:key_F9), Label.NoButton)
            )
          ),
          HSpacing(0.5)
        )
      )
      ret = nil
      begin
        ret = UI.UserInput
        if ret == :details
          if Convert.to_boolean(UI.QueryWidget(Id(:details), :Value))
            UI.ReplaceWidget(Id(:rp), VBox(Label(details)))
          else
            UI.ReplaceWidget(Id(:rp), Empty())
          end
        end
      end while ret != :yes && ret != :no
      UI.CloseDialog
      ret == :yes
    end

    # Initializes LDAP agent, offers to turn off TLS if it failed
    # @args arguments to use for initializaton (if empty, uses the current values)
    def LDAPInitWithTLSCheck(args)
      args = deep_copy(args)
      ret = ""
      if args == {}
        args = {
          "hostname"   => GetFirstServer(@server),
          "port"       => GetFirstPort(@server),
          "use_tls"    => @ldap_tls,
          "cacertdir"  => @tls_cacertdir,
          "cacertfile" => @tls_cacertfile
        }
      end
      init = Convert.to_boolean(SCR.Execute(path(".ldap"), args))
      # error message
      unknown = _("Unknown error. Perhaps 'yast2-ldap' is not available.")
      if init == nil
        ret = unknown
      else
        if !init
          errmap = LDAPErrorMap()
          if Ops.get_string(args, "use_tls", "") == "yes" &&
              Ops.get_boolean(errmap, "tls_error", false) &&
              ConnectWithoutTLS(errmap)
            Ops.set(args, "use_tls", "no")
            init = Convert.to_boolean(SCR.Execute(path(".ldap"), args))
            if init == nil
              ret = unknown
            elsif !init
              ret = LDAPError()
            else
              Builtins.y2milestone("switching TLS off...")
              @tls_switched_off = true
            end
          else
            ret = Ops.get_string(errmap, "msg", "")
            if Ops.get_string(errmap, "server_msg", "") != ""
              ret = Builtins.sformat(
                "%1\n%2",
                ret,
                Ops.get_string(errmap, "server_msg", "")
              )
            end
          end
        end
        @ldap_initialized = init
        @tls_when_initialized = Ops.get_string(args, "use_tls", "no") == "yes"
      end
      ret
    end

    # Binds to LDAP server
    # @param [String] pass password
    def LDAPBind(pass)
      ret = ""
      if pass != nil
        args = {}
        args = { "bind_dn" => @bind_dn, "bind_pw" => pass } if !@anonymous
        if !Convert.to_boolean(SCR.Execute(path(".ldap.bind"), args))
          ret = LDAPError()
        else
          @bound = true
        end
      end
      ret
    end

    # Asks user for bind_dn and password to LDAP server
    # @param anonymous if anonymous access could be allowed
    # @return password
    def GetLDAPPassword(enable_anonymous)
      Read() if @bind_dn.empty?
      UI.OpenDialog(
        Opt(:decorated),
        VBox(
          HSpacing(40),
          TextEntry(Id(:bdn), Opt(:hstretch), _("BindDN"), @bind_dn ),
          # password entering label
          Password(Id(:pw),   Opt(:hstretch), _("&LDAP Server Password")),
          # label
          Label(
            Builtins.sformat(
              _("Server: %1:%2"),
              GetFirstServer(@server),
              GetFirstPort(@server)
            )
          ),
          # label (%1 is admin DN - string)
          ButtonBox(
            PushButton(Id(:ok), Opt(:key_F10, :default), Label.OKButton),
            # button label
            PushButton(Id(:anon), Opt(:key_F6), _("&Anonymous Access")),
            PushButton(Id(:cancel), Opt(:key_F9), Label.CancelButton)
          )
        )
      )
      UI.ChangeWidget(Id(:anon), :Enabled, false) if !enable_anonymous
      UI.SetFocus(Id(:pw))
      ret = UI.UserInput
      pw = ""
      if ret == :ok
        pw       = Convert.to_string(UI.QueryWidget(Id(:pw), :Value))
        @bind_dn = Convert.to_string(UI.QueryWidget(Id(:bdn), :Value))
        @anonymous = false
      elsif ret == :cancel
        pw = nil
      else
        @anonymous = true
      end
      UI.CloseDialog
      pw
    end

    # Asks for LDAP password and tries to bind with it
    # @return password entered, nil on cancel
    def LDAPAskAndBind(enable_anonymous)
      return nil if Mode.commandline
      pw = GetLDAPPassword(enable_anonymous)
      if pw != nil
        ldap_msg = LDAPBind(pw)
        while pw != nil && ldap_msg != ""
          LDAPErrorMessage("bind", ldap_msg)
          pw = GetLDAPPassword(enable_anonymous)
          ldap_msg = LDAPBind(pw)
        end
      end
      pw
    end

    # Check if attribute allowes only single or multiple value
    # @param [String] attr attribute name
    # @return answer
    def SingleValued(attr)
      attr = Builtins.tolower(attr)
      if !Builtins.haskey(@attr_types, attr)
        attr_type = Convert.to_map(
          SCR.Read(path(".ldap.schema.at"), { "name" => attr })
        )
        attr_type = {} if attr_type == nil
        Ops.set(@attr_types, attr, attr_type)
      end
      Ops.get_boolean(@attr_types, [attr, "single"], false)
    end

    # Gets the description of attribute (from schema)
    # @param [String] attr attribute name
    # @return description
    def AttributeDescription(attr)
      if !Builtins.haskey(@attr_types, attr)
        attr_type = Convert.to_map(
          SCR.Read(path(".ldap.schema.at"), { "name" => attr })
        )
        attr_type = {} if attr_type == nil
        Ops.set(@attr_types, attr, attr_type)
      end
      Ops.get_string(@attr_types, [attr, "desc"], "")
    end

    # Returns true if given object class exists in schema
    # @param [String] class ObjectClass name
    def ObjectClassExists(_class)
      Convert.to_boolean(
        SCR.Read(path(".ldap.schema.oc.check"), { "name" => _class })
      )
    end

    # Returns true if given object class is of 'structural' type
    # @param [String] class ObjectClass name
    def ObjectClassStructural(_class)
      object_class = Convert.to_map(
        SCR.Read(path(".ldap.schema.oc"), { "name" => _class })
      )
      Ops.get_integer(object_class, "kind", 0) == 1
    end


    # Returns allowed and required attributes of given object class
    # Read it from LDAP if it was not done yet.
    # @param [String] class name of object class
    # @return attribute names (list of strings)
    def GetAllAttributes(_class)
      _class = Builtins.tolower(_class)
      if !Builtins.haskey(@object_classes, _class)
        object_class = Convert.to_map(
          SCR.Read(path(".ldap.schema.oc"), { "name" => _class })
        )
        object_class = {} if object_class == nil #TODO return from function?
        Ops.set(
          object_class,
          "all",
          Builtins.union(
            Ops.get_list(object_class, "may", []),
            Ops.get_list(object_class, "must", [])
          )
        )
        # read attributes of superior classes
        Builtins.foreach(Ops.get_list(object_class, "sup", [])) do |sup_oc|
          sup_all = GetAllAttributes(sup_oc)
          Ops.set(
            object_class,
            "all",
            Builtins.union(Ops.get_list(object_class, "all", []), sup_all)
          )
          Ops.set(
            object_class,
            "must",
            Builtins.union(
              Ops.get_list(object_class, "must", []),
              Ops.get_list(@object_classes, [sup_oc, "must"], [])
            )
          )
        end
        Ops.set(@object_classes, _class, object_class)
      end
      Ops.get_list(@object_classes, [_class, "all"], [])
    end

    # Returns required attributes of given object class
    # Read it from LDAP if it was not done yet.
    # @param [String] class name of object class
    # @return attribute names (list of strings)
    def GetRequiredAttributes(_class)
      _class = Builtins.tolower(_class)
      GetAllAttributes(_class) if !Builtins.haskey(@object_classes, _class)
      Ops.get_list(@object_classes, [_class, "must"], [])
    end

    def GetOptionalAttributes(_class)
      _class = Builtins.tolower(_class)
      GetAllAttributes(_class) if !Builtins.haskey(@object_classes, _class)
      Ops.get_list(@object_classes, [_class, "may"], [])
    end

    # Returns the list of all allowed and required attributes for each
    # object class, given in the list of object classes
    # @param [Array] classes list of object classes whose attributes we want
    # @return attribute names (list of strings)
    def GetObjectAttributes(classes)
      classes = deep_copy(classes)
      ret = []
      Builtins.foreach(
        Convert.convert(classes, :from => "list", :to => "list <string>")
      ) { |_class| ret = Builtins.union(ret, GetAllAttributes(_class)) }
      deep_copy(ret)
    end

    # For a given object, add all atributes this object is allowed to have
    # according to its "objectClass" value. Added attributes have empty values.
    # @param [Hash] object map describing LDAP entry
    # @return updated map
    def AddMissingAttributes(object)
      object = deep_copy(object)
      Builtins.foreach(Ops.get_list(object, "objectClass", [])) do |_class|
        Builtins.foreach(
          Convert.convert(
            GetAllAttributes(_class),
            :from => "list",
            :to   => "list <string>"
          )
        ) do |attr|
          if !Builtins.haskey(object, attr) &&
              !Builtins.haskey(object, Builtins.tolower(attr))
            object = Builtins.add(object, attr, [])
          end
        end
      end
      deep_copy(object)
    end

    # Prepare agent for later schema queries
    # (agent reads schema to its internal structures)
    # @return error message
    def InitSchema
      schemas = Convert.to_list(
        SCR.Read(
          path(".ldap.search"), #0:base
          { "base_dn" => "", "attrs" => ["subschemaSubentry"], "scope" => 0 }
        )
      )
      schema_dn = Ops.get_string(schemas, [0, "subschemaSubentry", 0], "")
      return LDAPError() if schemas == nil || schema_dn == ""

      if !Convert.to_boolean(
          SCR.Execute(path(".ldap.schema"), { "schema_dn" => schema_dn })
        )
        return LDAPError()
      end

      @schema_initialized = true
      ""
    end

    # In template object, convert the list of values
    # (which is in the form [ "a1=v1", "a2=v2"])
    # to map (in the form $[ "a1":"v1", "a2":"v2"]
    # @param [Hash] templ original template map
    # @return updated template map
    def ConvertDefaultValues(templ)
      templ = deep_copy(templ)
      template = Builtins.add(templ, "default_values", {})
      Builtins.foreach(Ops.get_list(templ, "suseDefaultValue", [])) do |value|
        lvalue = Builtins.splitstring(value, "=")
        at = Ops.get(lvalue, 0, "")
        v = Ops.greater_than(Builtins.size(lvalue), 1) ?
          # '=' could be part of value, so we cannot use lvalue[1]
          Builtins.substring(value, Ops.add(Builtins.search(value, "="), 1)) :
          ""
        Ops.set(template, ["default_values", at], v)
      end
      deep_copy(template)
    end

    # Read object templates from LDAP server
    # @return [String] error message
    def ReadTemplates
      @templates = {}
      all = Convert.to_map(
        SCR.Read(
          path(".ldap.search"),
          {
            "base_dn"      => @base_config_dn,
            "filter"       => "objectClass=suseObjectTemplate",
            "attrs"        => [],
            "scope"        => 2, # sub: all templates under config DN
            "map"          => true,
            "not_found_ok" => true
          }
        )
      )
      return LDAPError() if all == nil
      # create a helper map of default values inside ...
      @templates = Builtins.mapmap(
        Convert.convert(
          all,
          :from => "map",
          :to   => "map <string, map <string, any>>"
        )
      ) do |dn, templ|
        template = ConvertDefaultValues(templ)
        template = AddMissingAttributes(template)
        { dn => template }
      end
      ""
    end

    # Read configuration moduels from LDAP server
    # @return [String] error message
    def ReadConfigModules
      @config_modules = {}
      modules = Convert.to_map(
        SCR.Read(
          path(".ldap.search"),
          {
            "base_dn"      => @base_config_dn,
            "filter"       => "objectClass=suseModuleConfiguration",
            "attrs"        => [],
            "scope"        => 1, # one - deeper searches would have problems with
            # constructing the dn
            "map"          => true,
            "not_found_ok" => true
          }
        )
      )
      return LDAPError() if modules == nil
      @config_modules = Builtins.mapmap(
        Convert.convert(
          modules,
          :from => "map",
          :to   => "map <string, map <string, any>>"
        )
      ) { |dn, mod| { dn => AddMissingAttributes(mod) } }
      ""
    end

    # Search for one entry (=base scope) in LDAP directory
    # @param [String] dn DN of entry
    # @return [Hash] with entry values, empty map if nothing found, nil on error
    def GetLDAPEntry(dn)
      if !@ldap_initialized
        msg = LDAPInit()
        if msg != ""
          LDAPErrorMessage("init", msg)
          return nil
        end
      end
      if !@schema_initialized
        msg = InitSchema()
        if msg != ""
          LDAPErrorMessage("schema", msg)
          return nil
        end
      end
      if @bind_pass == nil && !@anonymous
        @bind_pass = LDAPAskAndBind(true)
        return nil if @bind_pass == nil
      end
      objects = Convert.to_list(
        SCR.Read(
          path(".ldap.search"),
          {
            "base_dn"      => dn,
            "attrs"        => [],
            "scope"        => 0, # only this one
            "not_found_ok" => true
          }
        )
      )
      if objects == nil
        LDAPErrorMessage("read", LDAPError())
        return nil
      end
      Ops.get_map(objects, 0, {})
    end

    # Check for existence of parent object of given DN in LDAP tree
    # return the answer
    def ParentExists(dn)
      return false if !Builtins.issubstring(dn, ",")

      parent = Builtins.substring(dn, Ops.add(Builtins.search(dn, ","), 1))
      object = GetLDAPEntry(parent)
      return false if object == nil
      if object == {}
        if !@use_gui
          Builtins.y2error(
            "A direct parent for DN %1 does not exist in the LDAP directory. The object with the selected DN cannot be created.",
            dn
          )
          return false
        end
        # error message, %1 is DN
        Popup.Error(
          Builtins.sformat(
            _(
              "A direct parent for DN '%1' \n" +
                "does not exist in the LDAP directory.\n" +
                "The object with the selected DN cannot be created.\n"
            ),
            dn
          )
        )
        return false
      end
      true
    end

    # Return main configuration object DN
    def GetMainConfigDN
      @base_config_dn
    end

    # Return the map of configuration modules (new copy)
    # (in the form $[ DN: $[ map_of_one_module] ])
    def GetConfigModules
      Builtins.eval(@config_modules)
    end

    # Return the map of templates (new copy)
    def GetTemplates
      Builtins.eval(@templates)
    end

    # Return list of default object classes for user or group
    # There is fixed list here, it is not saved anywhere (only in default
    # users plugin for LDAP objects)
    # @param [Hash] template used for differ if we need user or group list
    def GetDefaultObjectClasses(template)
      template = deep_copy(template)
      ocs = Builtins.maplist(Ops.get_list(template, "objectClass", [])) do |c|
        Builtins.tolower(c)
      end

      if Builtins.contains(ocs, "susegrouptemplate")
        return ["top", "posixGroup", "groupOfNames"] 
        # TODO sometimes there is groupofuniquenames...
      elsif Builtins.contains(ocs, "suseusertemplate")
        return ["top", "posixAccount", "shadowAccount", "InetOrgPerson"]
      end
      []
    end

    # Searches for DN's of all objects defined by filter in given base ("sub")
    # @param [String] base search base
    # @param [String] search_filter if filter is empty, "objectClass=*" is used
    # @return [Array] of DN's (list of strings)
    def ReadDN(base, search_filter)
      all = Convert.convert(
        SCR.Read(
          path(".ldap.search"),
          {
            "base_dn"   => base,
            "filter"    => search_filter,
            "attrs"     => ["cn"], # not necessary, just not read all values
            "attrsOnly" => true,
            "scope"     => 2,
            "dn_only"   => true
          }
        ),
        :from => "any",
        :to   => "list <string>"
      )
      if all == nil
        LDAPErrorMessage("read", LDAPError())
        return []
      end
      deep_copy(all)
    end

    # Returns DN's of groups (objectClass=posixGroup) in given base
    # @param [String] base LDAP search base
    # @return groups (list of strings)
    def GetGroupsDN(base)
      @groups_dn = ReadDN(base, "objectClass=posixGroup") if @groups_dn == []
      deep_copy(@groups_dn)
    end

    # Writes map of objects to LDAP
    # @param [Hash] objects map of objects to write. It is in the form:
    # $[ DN: (map) attribute_values]
    # @example TODO
    # @return error map (empty on success)
    def WriteToLDAP(objects)
      objects = deep_copy(objects)
      ret = {}
      Builtins.foreach(
        Convert.convert(objects, :from => "map", :to => "map <string, map>")
      ) do |dn, object|
        next if ret != {}
        action = Ops.get_string(object, "modified", "")
        if action != ""
          object = Builtins.remove(object, "modified")
        else
          next
        end
        # convert the default values back to the LDAP format
        if Builtins.haskey(object, "default_values")
          Ops.set(
            object,
            "suseDefaultValue",
            Builtins.maplist(Ops.get_map(object, "default_values", {})) do |key, val|
              Builtins.sformat("%1=%2", key, val)
            end
          )
          object = Builtins.remove(object, "default_values")
        end
        if action == "added"
          if !SCR.Write(path(".ldap.add"), { "dn" => dn }, object)
            ret = LDAPErrorMap()
          end
        end
        if action == "edited"
          if !SCR.Write(
              path(".ldap.modify"),
              { "dn" => dn, "check_attrs" => true },
              object
            )
            ret = LDAPErrorMap()
          end
        end
        if action == "renamed"
          arg_map = {
            "dn"          => Ops.get_string(object, "old_dn", dn),
            "check_attrs" => true
          }
          if Builtins.tolower(dn) !=
              Builtins.tolower(Ops.get_string(object, "old_dn", dn))
            Ops.set(arg_map, "new_dn", dn)
            Ops.set(arg_map, "deleteOldRDN", true)
            Ops.set(arg_map, "subtree", true)
          end
          if Builtins.haskey(object, "old_dn")
            object = Builtins.remove(object, "old_dn")
          end
          if !SCR.Write(path(".ldap.modify"), arg_map, object)
            ret = LDAPErrorMap()
          end
        end
        if action == "deleted"
          if Ops.get_string(object, "old_dn", dn) != dn
            dn = Ops.get_string(object, "old_dn", dn)
          end
          if !SCR.Write(path(".ldap.delete"), { "dn" => dn })
            ret = LDAPErrorMap()
          end
        end
      end
      deep_copy(ret)
    end

    # Writes map of objects to LDAP. Ask for password, when needed and
    # shows the error message when necessary.
    # @return success
    def WriteLDAP(objects)
      objects = deep_copy(objects)
      error = {}
      @bind_pass = LDAPAskAndBind(false) if @anonymous || @bind_pass == nil
      # nil means "canceled"
      if @bind_pass != nil
        error = WriteToLDAP(objects)
        if error != {}
          msg = Ops.get_string(error, "msg", "")
          if Ops.get_string(error, "server_msg", "") != ""
            msg = Ops.add(
              Ops.add(msg, "\n"),
              Ops.get_string(error, "server_msg", "")
            )
          end
          LDAPErrorMessage("write", msg)
        end
      end
      error == {} && @bind_pass != nil
    end

    # If a file does not + entry, add it.
    # @param   is login allowed?
    # @return  success?
    def WritePlusLine(login)
      file = "/etc/passwd"
      what = "+::::::"
      what = "+::::::/sbin/nologin" if !login

      if !@passwd_read
        if !Convert.to_boolean(
            SCR.Execute(path(".passwd.init"), { "base_directory" => "/etc" })
          )
          Builtins.y2error("error: %1", SCR.Read(path(".passwd.error")))
          return false
        else
          @passwd_read = true
          @plus_lines_passwd = Convert.convert(
            SCR.Read(path(".passwd.passwd.pluslines")),
            :from => "any",
            :to   => "list <string>"
          )
        end
      end

      plus_lines = deep_copy(@plus_lines_passwd)

      if !Builtins.contains(plus_lines, what)
        plus_lines = Builtins.maplist(plus_lines) do |plus_line|
          next what if !login && plus_line == "+::::::"
          if login && Builtins.issubstring(plus_line, ":/sbin/nologin")
            next what
          end
          plus_line
        end
        if !Builtins.contains(plus_lines, what)
          plus_lines = Builtins.add(plus_lines, what)
        end

        if SCR.Write(path(".passwd.passwd.pluslines"), plus_lines)
          SCR.Execute(
            path(".target.bash"),
            Builtins.sformat("/bin/cp %1 %1.YaST2save", file)
          )
          # empty map as a parameter means "use data you have read"
          if !SCR.Write(path(".passwd.users"), {})
            Report.Error(Message.ErrorWritingFile(file))
            return false
          end
        end
      end

      file = "/etc/shadow"
      what = "+"
      plus_lines = Convert.convert(
        SCR.Read(path(".passwd.shadow.pluslines")),
        :from => "any",
        :to   => "list <string>"
      )

      if !Builtins.contains(plus_lines, what) &&
          !Builtins.contains(plus_lines, "+::::::::")
        plus_lines = Builtins.add(plus_lines, what)

        if SCR.Write(path(".passwd.shadow.pluslines"), plus_lines)
          SCR.Execute(
            path(".target.bash"),
            Builtins.sformat("/bin/cp %1 %1.YaST2save", file)
          )
          # empty map as a parameter means "use data you have read"
          if !SCR.Write(path(".passwd.shadow"), {})
            Report.Error(Message.ErrorWritingFile(file))
            return false
          end
        end
      end

      nil
    end

    # Check the server if it is NDS (novell directory service)
    def CheckNDS
      if !@ldap_initialized
        msg = LDAPInit()
        if msg != ""
          # no popup: see bug #132909
          return false
        end
      end

      vendor = Convert.to_list(
        SCR.Read(
          path(".ldap.search"),
          {
            "base_dn" => "",
            "scope"   => 0,
            "attrs"   => ["vendorVersion", "vendorName"]
          }
        )
      )

      Builtins.y2debug("vendor: %1", vendor)
      output = Ops.get_map(vendor, 0, {})
      Builtins.foreach(output) do |attr, value|
        if Builtins.issubstring(Ops.get_string(value, 0, ""), "Novell")
          Builtins.y2debug("value: %1", Ops.get_string(value, 0, ""))
          @nds = true
        end
      end

      @nds_checked = true
      @nds
    end


    # Check if base config DN belongs to some existing object and offer
    # creating it if necessary
    def CheckBaseConfig(dn)
      object = GetLDAPEntry(dn)
      return false if object == nil
      if object == {}
        # yes/no popup, %1 is value of DN
        if !@use_gui ||
            Popup.YesNo(
              Builtins.sformat(
                _(
                  "No entry with DN '%1'\nexists on the LDAP server. Create it now?\n"
                ),
                dn
              )
            )
          return false if !ParentExists(dn)
          config_object = {
            "objectClass" => ["top", "organizationalUnit"],
            "modified"    => "added",
            "ou"          => get_cn(dn)
          }
          if @nds
            Ops.set(
              config_object,
              "acl",
              [
                "3#subtree#[Public]#[All Attributes Rights]",
                "1#subtree#[Public]#[Entry Rights]"
              ]
            )
          end
          return WriteLDAP({ dn => config_object })
        end
        return false
      end
      true
    end

    # Set the value of bind_pass variable
    # @param [String] pass new password valure
    def SetBindPassword(pass)
      @bind_pass = pass

      nil
    end

    # Set the value of 'anonymous' variable (= bind without password)
    # @param [Boolean] anon new value
    def SetAnonymous(anon)
      @anonymous = anon

      nil
    end

    # Set the value of 'use_gui' variable (= show error popups)
    # @param [Boolean] gui new value
    def SetGUI(gui)
      @use_gui = gui

      nil
    end

    # Get RDN (relative distinguished name) from dn
    def get_rdn(dn)
      dn_list = Builtins.splitstring(dn, ",")
      Ops.get_string(dn_list, 0, dn)
    end

    # Get first value from dn (don't have to be "cn")
    def get_cn(dn)
      rdn = get_rdn(dn)
      Builtins.issubstring(rdn, "=") ?
        Builtins.substring(rdn, Ops.add(Builtins.search(rdn, "="), 1)) :
        rdn
    end

    # Create DN from cn by adding base config DN
    # (Can't work in general cases!)
    def get_dn(cn)
      Builtins.sformat("cn=%1,%2", cn, @base_config_dn)
    end

    # Create new DN from DN by changing leading cn value
    # (Can't work in general cases!)
    def get_new_dn(cn, dn)
      Builtins.tolower(
        Builtins.sformat(
          "cn=%1%2",
          cn,
          Builtins.issubstring(dn, ",") ?
            Builtins.substring(dn, Builtins.search(dn, ",")) :
            ""
        )
      )
    end

    # Get string value of attribute from map.
    # (Generaly, it is supposed to be list or string.)
    def get_string(object, attr)
      object = deep_copy(object)
      if Ops.is_list?(Ops.get(object, attr))
        return Ops.get_string(object, [attr, 0], "")
      end
      Ops.get_string(object, attr, "")
    end

    publish :variable => :use_gui, :type => "boolean"
    publish :variable => :base_config_dn, :type => "string"
    publish :function => :get_rdn, :type => "string (string)", :private => true
    publish :function => :get_cn, :type => "string (string)", :private => true
    publish :function => :get_dn, :type => "string (string)", :private => true
    publish :function => :get_new_dn, :type => "string (string, string)", :private => true
    publish :function => :get_string, :type => "string (map, string)", :private => true
    publish :variable => :required_packages, :type => "list <string>"
    publish :variable => :write_only, :type => "boolean"
    publish :variable => :start, :type => "boolean"
    publish :variable => :nis_available, :type => "boolean"
    publish :variable => :_autofs_allowed, :type => "boolean"
    publish :variable => :_start_autofs, :type => "boolean"
    publish :variable => :login_enabled, :type => "boolean"
    publish :variable => :member_attribute, :type => "string"
    publish :variable => :server, :type => "string"
    publish :variable => :modified, :type => "boolean"
    publish :variable => :openldap_modified, :type => "boolean"
    publish :variable => :base_dn, :type => "string", :private => true
    publish :variable => :base_dn_changed, :type => "boolean", :private => true
    publish :variable => :ldap_tls, :type => "boolean"
    publish :variable => :tls_cacertdir, :type => "string"
    publish :variable => :tls_cacertfile, :type => "string"
    publish :variable => :tls_checkpeer, :type => "string"
    publish :variable => :pam_password, :type => "string"
    publish :variable => :plus_lines_passwd, :type => "list <string>"
    publish :variable => :default_port, :type => "integer"
    publish :variable => :file_server, :type => "boolean"
    publish :variable => :nss_base_passwd, :type => "string"
    publish :variable => :nss_base_shadow, :type => "string"
    publish :variable => :nss_base_group, :type => "string"
    publish :variable => :user_base, :type => "string"
    publish :variable => :group_base, :type => "string"
    publish :variable => :nsswitch, :type => "map", :private => true
    publish :variable => :anonymous, :type => "boolean"
    publish :variable => :bind_pass, :type => "string"
    publish :variable => :bind_dn, :type => "string"
    publish :variable => :current_module_dn, :type => "string"
    publish :variable => :current_template_dn, :type => "string"
    publish :variable => :nds, :type => "boolean"
    publish :variable => :tls_switched_off, :type => "boolean"
    publish :variable => :nds_checked, :type => "boolean", :private => true
    publish :variable => :oes, :type => "boolean", :private => true
    publish :variable => :new_objects, :type => "map"
    publish :variable => :base_template_dn, :type => "string"
    publish :variable => :ldap_modified, :type => "boolean"
    publish :variable => :config_modules, :type => "map"
    publish :variable => :templates, :type => "map"
    publish :variable => :bound, :type => "boolean"
    publish :variable => :groups_dn, :type => "list"
    publish :variable => :object_classes, :type => "map"
    publish :variable => :attr_types, :type => "map"
    publish :variable => :hash_schemas, :type => "list"
    publish :variable => :available_config_modules, :type => "list <string>"
    publish :variable => :initial_defaults, :type => "map"
    publish :variable => :initial_defaults_used, :type => "boolean"
    publish :variable => :schema_initialized, :type => "boolean"
    publish :variable => :ldap_initialized, :type => "boolean"
    publish :variable => :tls_when_initialized, :type => "boolean"
    publish :variable => :read_settings, :type => "boolean"
    publish :variable => :restart_sshd, :type => "boolean"
    publish :variable => :passwd_read, :type => "boolean", :private => true
    publish :variable => :pam_nss_packages, :type => "list <string>"
    publish :variable => :sssd_packages, :type => "list <string>"
    publish :variable => :sssd, :type => "boolean"
    publish :variable => :ldap_error_hints, :type => "map"
    publish :function => :BaseDNChanged, :type => "boolean ()"
    publish :function => :DomainChanged, :type => "boolean ()"
    publish :function => :GetBaseDN, :type => "string ()"
    publish :function => :GetDomain, :type => "string ()"
    publish :function => :SetBaseDN, :type => "void (string)"
    publish :function => :SetDomain, :type => "void (string)"
    publish :function => :SetDefaults, :type => "boolean (map)"
    publish :function => :SetReadSettings, :type => "boolean (boolean)"
    publish :function => :Export, :type => "map ()"
    publish :function => :ReadLdapConfEntry, :type => "string (string, string)", :private => true
    publish :function => :ReadLdapConfEntries, :type => "list <string> (string)", :private => true
    publish :function => :WriteLdapConfEntry, :type => "void (string, string)", :private => true
    publish :function => :WriteLdapConfEntries, :type => "void (string, list <string>)", :private => true
    publish :function => :AddLdapConfEntry, :type => "void (string, string)", :private => true
    publish :function => :CheckOES, :type => "boolean ()"
    publish :function => :uri2servers, :type => "string (string)", :private => true
    publish :function => :ReadLdapHosts, :type => "string ()"
    publish :function => :Read, :type => "boolean ()"
    publish :function => :LDAPErrorMessage, :type => "void (string, string)"
    publish :function => :LDAPErrorMap, :type => "map ()"
    publish :function => :LDAPError, :type => "string ()"
    publish :function => :GetBindDN, :type => "string ()"
    publish :function => :GetFirstServer, :type => "string (string)"
    publish :function => :GetFirstPort, :type => "integer (string)"
    publish :function => :LDAPClose, :type => "boolean ()"
    publish :function => :LDAPInit, :type => "string ()"
    publish :function => :LDAPInitArgs, :type => "map (map)"
    publish :function => :CheckLDAPConnection, :type => "boolean (map)"
    publish :function => :ConnectWithoutTLS, :type => "boolean (map)"
    publish :function => :LDAPInitWithTLSCheck, :type => "string (map)"
    publish :function => :LDAPBind, :type => "string (string)"
    publish :function => :GetLDAPPassword, :type => "string (boolean)"
    publish :function => :LDAPAskAndBind, :type => "string (boolean)"
    publish :function => :SingleValued, :type => "boolean (string)"
    publish :function => :AttributeDescription, :type => "string (string)"
    publish :function => :ObjectClassExists, :type => "boolean (string)"
    publish :function => :ObjectClassStructural, :type => "boolean (string)"
    publish :function => :GetAllAttributes, :type => "list (string)"
    publish :function => :GetRequiredAttributes, :type => "list <string> (string)"
    publish :function => :GetOptionalAttributes, :type => "list <string> (string)"
    publish :function => :GetObjectAttributes, :type => "list (list)"
    publish :function => :AddMissingAttributes, :type => "map (map)"
    publish :function => :InitSchema, :type => "string ()"
    publish :function => :ConvertDefaultValues, :type => "map (map)"
    publish :function => :ReadTemplates, :type => "string ()"
    publish :function => :ReadConfigModules, :type => "string ()"
    publish :function => :GetLDAPEntry, :type => "map (string)"
    publish :function => :ParentExists, :type => "boolean (string)"
    publish :function => :GetMainConfigDN, :type => "string ()"
    publish :function => :GetConfigModules, :type => "map ()"
    publish :function => :GetTemplates, :type => "map ()"
    publish :function => :GetDefaultObjectClasses, :type => "list (map)"
    publish :function => :ReadDN, :type => "list <string> (string, string)"
    publish :function => :GetGroupsDN, :type => "list (string)"
    publish :function => :WriteToLDAP, :type => "map (map)"
    publish :function => :WriteLDAP, :type => "boolean (map)"
    publish :function => :WritePlusLine, :type => "boolean (boolean)"
    publish :function => :CheckNDS, :type => "boolean ()"
    publish :function => :Write, :type => "symbol (block <boolean>)"
    publish :function => :WriteNow, :type => "boolean ()"
    publish :function => :CheckBaseConfig, :type => "boolean (string)"
    publish :function => :SetBindPassword, :type => "void (string)"
    publish :function => :SetAnonymous, :type => "void (boolean)"
    publish :function => :SetGUI, :type => "void (boolean)"
    publish :function => :get_rdn, :type => "string (string)"
    publish :function => :get_cn, :type => "string (string)"
    publish :function => :get_dn, :type => "string (string)"
    publish :function => :get_new_dn, :type => "string (string)"
    publish :function => :get_string, :type => "string (string)"
  end

  Ldap = LdapClass.new
  Ldap.main
end
