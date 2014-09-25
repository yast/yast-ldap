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

# File:	include/ldap/ui.ycp
# Package:	Configuration of LDAP
# Summary:	User interface functions.
# Authors:	Thorsten Kukuk <kukuk@suse.de>
#		Anas Nashif <nashif@suse.de>
#
# $Id$
#
# All user interface functions.
module Yast
  module LdapUiInclude
    def initialize_ldap_ui(include_target)
      Yast.import "UI"
      textdomain "ldap-client"

      Yast.import "Address"
      Yast.import "Autologin"
      Yast.import "Directory"
      Yast.import "FileUtils"
      Yast.import "Label"
      Yast.import "Ldap"
      Yast.import "LdapPopup"
      Yast.import "Message"
      Yast.import "Mode"
      Yast.import "Package"
      Yast.import "Pam"
      Yast.import "Popup"
      Yast.import "Report"
      Yast.import "Service"
      Yast.import "SLPAPI"
      Yast.import "Stage"
      Yast.import "Wizard"

      Yast.include include_target, "ldap/routines.rb"
    end

    def Modified
      Ldap.modified || Ldap.ldap_modified
    end

    # The dialog that appears when the [Abort] button is pressed.
    # @return `abort if user really wants to abort, `back otherwise
    def ReallyAbort
      ret = Modified() || Stage.cont ? Popup.ReallyAbort(true) : true

      if ret
        return :abort
      else
        return :back
      end
    end

    # Read settings dialog
    # @return `abort if aborted and `next otherwise
    def ReadDialog
      ret = Ldap.Read
      ret ? :next : :abort
    end

    # Write settings dialog
    # @return `next
    def WriteDialog
      # popup text
      abort = lambda do
        if UI.PollInput == :abort &&
            # popup text
            Popup.YesNo(_("Really abort the writing process?"))
          next true
        end
        false
      end

      if Modified()
        # help text
        Wizard.RestoreHelp(_("Writing LDAP Client Settings"))
        return Ldap.Write(abort)
      end
      :next
    end

    # Initialize connection to LDAP server, bind and read the settings.
    # Everything is done before entering the Module Configuration Dialog.
    def LDAPReadDialog
      msg = ""
      read_now = false

      if !Ldap.bound || Modified()
        if !Ldap.bound || Ldap.modified
          # re-init/re-bind only when server information was changed (#39908)
          if !Ldap.bound || Ldap.old_server != Ldap.server || Ldap.BaseDNChanged
            msg = Ldap.LDAPInitWithTLSCheck({})
            if msg != ""
              Ldap.LDAPErrorMessage("init", msg)
              return :back
            end
          end

          if !Ldap.bound || Ldap.old_server != Ldap.server
            # Ldap::bind_pass might exist from server proposal...
            if Stage.cont && Ldap.bind_pass != nil
              msg = Ldap.LDAPBind(Ldap.bind_pass)
              if msg != ""
                Ldap.LDAPErrorMessage("bind", msg)
                Ldap.bind_pass = Ldap.LDAPAskAndBind(true)
              end
            else
              Ldap.bind_pass = Ldap.LDAPAskAndBind(true)
            end
            return :back if Ldap.bind_pass == nil

            read_now = true

            msg = Ldap.InitSchema
            Ldap.LDAPErrorMessage("schema", msg) if msg != ""
          end
        end
        return :back if !Ldap.CheckBaseConfig(Ldap.base_config_dn)
        if read_now || Ldap.modified && !Ldap.ldap_modified ||
            Ldap.ldap_modified &&
              Popup.AnyQuestion(
                Popup.NoHeadline,
                # yes/no popup
                _(
                  "If you reread settings from the server,\nall changes will be lost. Really reread?\n"
                ),
                Label.YesButton,
                Label.NoButton,
                :focus_no
              )
          msg = Ldap.ReadConfigModules
          Ldap.LDAPErrorMessage("read", msg) if msg != ""

          msg = Ldap.ReadTemplates
          Ldap.LDAPErrorMessage("read", msg) if msg != ""

          Ldap.ldap_modified = false
        end
        Ldap.bound = true
      end
      :next
    end

    # Dialog for configuration one object template
    def TemplateConfigurationDialog(templ)
      templ = deep_copy(templ)
      # help text 1/3
      help_text = _(
        "<p>Configure the template used for creating \nnew objects (like users or groups).</p>\n"
      ) +
        # help text 2/3
        _(
          "<p>Edit the template attribute values with <b>Edit</b>.\nChanging the <b>cn</b> value renames the template.</p>\n"
        ) +
        # help text 3/3
        _(
          "<p>The second table contains a list of <b>default values</b> used\n" +
            "for new objects. Modify the list by adding new values, editing or\n" +
            "removing current ones.</p>\n"
        )

      template_dn = Ldap.current_template_dn

      table_items = []
      template = Convert.convert(
        Builtins.eval(templ),
        :from => "map",
        :to   => "map <string, any>"
      )

      # helper function converting list value to string
      to_table = lambda do |attr, val|
        val = deep_copy(val)
        if Ldap.SingleValued(attr) || attr == "cn"
          return Ops.get(val, 0, "")
        elsif Builtins.contains(
            ["susesecondarygroup", "susedefaulttemplate"],
            Builtins.tolower(attr)
          )
          return Builtins.mergestring(val, " ")
        else
          return Builtins.mergestring(val, ",")
        end
      end

      Builtins.foreach(template) do |attr, value|
        val = deep_copy(value)
        # do not show internal attributes
        if Builtins.contains(
            [
              "susedefaultvalue",
              "default_values",
              "objectclass",
              "modified",
              "old_dn"
            ],
            Builtins.tolower(attr)
          )
          next
        end
        if Ops.is_list?(value)
          val = to_table.call(
            attr,
            Convert.convert(val, :from => "any", :to => "list <string>")
          )
        end
        table_items = Builtins.add(table_items, Item(Id(attr), attr, val))
      end

      default_items = []
      default_values = Ops.get_map(template, "default_values", {})
      Builtins.foreach(default_values) do |attr, value|
        default_items = Builtins.add(default_items, Item(Id(attr), attr, value))
      end

      contents = HBox(
        HSpacing(1.5),
        VBox(
          VSpacing(0.5),
          Table(
            Id(:table),
            Opt(:notify),
            Header(
              # table header 1/2
              _("Attribute"),
              # table header 2/2
              _("Value")
            ),
            table_items
          ),
          HBox(PushButton(Id(:edit), Label.EditButton), HStretch()),
          # label (table folows)
          Left(Label(_("Default Values for New Objects"))),
          Table(
            Id(:defaults),
            Opt(:notify),
            Header(
              # table header 1/2
              _("Attribute of Object"),
              # table header 2/2
              _("Default Value")
            ),
            default_items
          ),
          HBox(
            # button label (with non-default shortcut)
            PushButton(Id(:add_dfl), Opt(:key_F3), _("A&dd")),
            # button label
            PushButton(Id(:edit_dfl), Opt(:key_F4), _("&Edit")),
            PushButton(Id(:delete_dfl), Opt(:key_F5), Label.DeleteButton),
            HStretch()
          ),
          VSpacing(0.5)
        ),
        HSpacing(1.5)
      )

      Wizard.OpenNextBackDialog
      # dialog label
      Wizard.SetContentsButtons(
        _("Object Template Configuration"),
        contents,
        help_text,
        Label.CancelButton,
        Label.OKButton
      )
      Wizard.HideAbortButton

      UI.SetFocus(Id(:table)) if Ops.greater_than(Builtins.size(table_items), 0)
      UI.ChangeWidget(Id(:edit_dfl), :Enabled, default_items != [])
      UI.ChangeWidget(Id(:delete_dfl), :Enabled, default_items != [])

      result = nil
      while true
        result = UI.UserInput
        attr = Convert.to_string(UI.QueryWidget(Id(:table), :CurrentItem))

        # edit attribute
        if result == :edit || result == :table
          next if attr == nil
          value = Ops.get_list(template, attr, [])
          offer = []
          conflicts = []
          if Builtins.tolower(attr) == "susesecondarygroup"
            offer = Ldap.GetGroupsDN(Ldap.GetBaseDN)
          end
          if Builtins.tolower(attr) == "susenamingattribute"
            classes = Ldap.GetDefaultObjectClasses(template)
            offer = Ldap.GetObjectAttributes(classes)
          end
          if attr == "cn"
            base = Builtins.issubstring(template_dn, ",") ?
              Builtins.substring(
                template_dn,
                Ops.add(Builtins.search(template_dn, ","), 1)
              ) :
              ""
            Builtins.foreach(Ldap.ReadDN(base, "")) do |dn|
              if Builtins.substring(dn, 0, 3) == "cn="
                conflicts = Builtins.add(conflicts, get_cn(dn))
              end
            end
          end
          value = LdapPopup.EditAttribute(
            {
              "attr"      => attr,
              "value"     => value,
              "conflicts" => conflicts,
              "single"    => Ldap.SingleValued(attr) || attr == "cn",
              "offer"     => offer,
              "browse"    => Builtins.tolower(attr) == "susesecondarygroup"
            }
          )

          next if value == Ops.get_list(template, attr, [])
          UI.ChangeWidget(
            Id(:table),
            term(:Item, attr, 1),
            to_table.call(attr, value)
          )
          Ops.set(template, attr, value)
        end
        # add default value
        if result == :add_dfl
          conflicts = Builtins.maplist(default_values) { |attr3, val| attr3 }
          classes = Ldap.GetDefaultObjectClasses(template)
          available = Ldap.GetObjectAttributes(classes)
          # filter out objectclass
          dfl = LdapPopup.AddDefaultValue(
            Builtins.sort(available),
            Builtins.add(conflicts, "objectClass")
          )
          next if Ops.get_string(dfl, "value", "") == ""
          attr2 = Ops.get_string(dfl, "attr", "")
          Ops.set(default_values, attr2, Ops.get_string(dfl, "value", ""))
          default_items = Builtins.add(
            default_items,
            Item(Id(attr2), attr2, Ops.get_string(dfl, "value", ""))
          )
          UI.ChangeWidget(Id(:defaults), :Items, default_items)
          UI.ChangeWidget(Id(:edit_dfl), :Enabled, default_items != [])
          UI.ChangeWidget(Id(:delete_dfl), :Enabled, default_items != [])
        end
        # edit default value
        if result == :edit_dfl || result == :defaults
          attr = Convert.to_string(UI.QueryWidget(Id(:defaults), :CurrentItem))
          next if attr == nil
          value = Ops.get(default_values, attr, "")
          l_value = LdapPopup.EditAttribute(
            { "attr" => attr, "value" => [value], "single" => true }
          )
          next if Ops.get_string(l_value, 0, "") == value
          value = Ops.get_string(l_value, 0, "")
          UI.ChangeWidget(Id(:defaults), term(:Item, attr, 1), value)
          Ops.set(default_values, attr, value)
        end
        # delete default value
        if result == :delete_dfl
          attr = Convert.to_string(UI.QueryWidget(Id(:defaults), :CurrentItem))
          next if attr == nil
          # yes/no popup, %1 is name
          if !Popup.YesNo(
              Builtins.sformat(
                _("Really delete default attribute \"%1\"?"),
                attr
              )
            )
            next
          end
          default_values = Builtins.remove(default_values, attr)
          default_items = Builtins.filter(default_items) do |it|
            Ops.get_string(it, 1, "") != attr
          end
          UI.ChangeWidget(Id(:defaults), :Items, default_items)
          UI.ChangeWidget(Id(:edit_dfl), :Enabled, default_items != [])
          UI.ChangeWidget(Id(:delete_dfl), :Enabled, default_items != [])
        end
        if Ops.is_symbol?(result) &&
            Builtins.contains(
              [:back, :cancel, :abort],
              Convert.to_symbol(result)
            )
          break
        end
        if result == :next
          cont = false

          # check the template required attributes...
          Builtins.foreach(Ops.get_list(template, "objectClass", [])) do |oc|
            next if cont
            Builtins.foreach(Ldap.GetRequiredAttributes(oc)) do |attr2|
              val = Ops.get(template, attr2)
              if !cont && val == nil || val == [] || val == ""
                #error popup, %1 is attribute name
                Popup.Error(
                  Builtins.sformat(
                    _("The \"%1\" attribute is mandatory.\nEnter a value."),
                    attr2
                  )
                )
                UI.SetFocus(Id(:table))
                cont = true
              end
            end
          end
          next if cont
          Ops.set(template, "default_values", default_values)
          break
        end
      end
      Wizard.CloseDialog
      deep_copy(template)
    end

    # Dialog for configuration of one "configuration module"
    def ModuleConfigurationDialog
      # helptext 1/4
      help_text = _(
        "<p>Manage the configuration stored in the LDAP directory.</p>"
      ) +
        # helptext 2/4
        _(
          "<p>Each configuration set is called a \"configuration module.\" If there\n" +
            "is no configuration module in the provided location (base configuration),\n" +
            "create one with <b>New</b>. Delete the current module\n" +
            "using <b>Delete</b>.</p>\n"
        ) +
        # helptext 3/4
        _(
          "<p>Edit the values of attributes in the table with <b>Edit</b>.\n" +
            "Some values have special meanings, for example, changing the <b>cn</b> value renames the\n" +
            "current module.</p>\n"
        ) +
        # helptext 4/4
        _(
          "<p>To configure the default template of the current module,\n" +
            "click <b>Configure Template</b>.\n" +
            "</p>\n"
        )

      current_dn = Ldap.current_module_dn
      modules_attrs_items = {} # map of list (table items), index is cn
      modules = Convert.convert(
        Ldap.GetConfigModules,
        :from => "map",
        :to   => "map <string, map <string, any>>"
      )
      templates = Convert.convert(
        Ldap.GetTemplates,
        :from => "map",
        :to   => "map <string, map <string, any>>"
      )
      names = []
      templates_dns = Builtins.maplist(templates) { |dn, t| dn }

      # Helper for creating table items in ModuleConfiguration Dialog
      create_attrs_items = lambda do |cn|
        attrs_items = []
        dn = get_dn(cn)
        dn = Builtins.tolower(dn) if !Builtins.haskey(modules, dn)
        Builtins.foreach(Ops.get(modules, dn, {})) do |attr, value|
          val = deep_copy(value)
          if Builtins.contains(
              ["objectclass", "modified", "old_dn"],
              Builtins.tolower(attr)
            )
            next
          end
          if Ops.is_list?(value)
            lvalue = Convert.to_list(value)
            if Ldap.SingleValued(attr) || attr == "cn"
              val = Ops.get_string(lvalue, 0, "")
            else
              val = Builtins.mergestring(
                Convert.convert(value, :from => "any", :to => "list <string>"),
                ","
              )
            end
          end
          attrs_items = Builtins.add(attrs_items, Item(Id(attr), attr, val))
        end

        deep_copy(attrs_items)
      end

      Builtins.foreach(modules) do |dn, mod|
        cn = get_string(mod, "cn")
        next if cn == ""
        names = Builtins.add(names, cn)
        # attributes for table
        Ops.set(modules_attrs_items, cn, create_attrs_items.call(cn))
        current_dn = dn if current_dn == ""
      end
      current_cn = Ops.get_string(modules, [current_dn, "cn", 0]) do
        get_cn(current_dn)
      end

      # Helper for updating widgets in ModuleConfiguration Dialog
      replace_module_names = lambda do
        modules_items = [] # list of module names
        Builtins.foreach(names) do |cn|
          if Builtins.tolower(cn) == Builtins.tolower(current_cn)
            modules_items = Builtins.add(modules_items, Item(Id(cn), cn, true))
          else
            modules_items = Builtins.add(modules_items, Item(Id(cn), cn))
          end
        end
        UI.ReplaceWidget(
          Id(:rp_modnames),
          Left(
            ComboBox(
              Id(:modules),
              Opt(:notify),
              # combobox label
              _("Configuration &Module"),
              modules_items
            )
          )
        )
        ena = names != []
        UI.ChangeWidget(Id(:delete), :Enabled, ena)
        UI.ChangeWidget(Id(:edit), :Enabled, ena)
        UI.ChangeWidget(Id(:modules), :Enabled, ena)

        nil
      end

      # Helper for updating widgets in ModuleConfiguration Dialog
      replace_templates_items = lambda do
        items = Builtins.maplist(
          Ops.get_list(modules, [current_dn, "suseDefaultTemplate"], [])
        ) { |dn| Item(Id(dn), dn) }
        UI.ReplaceWidget(
          Id(:rp_templs),
          PushButton(
            Id(:templ_pb),
            Opt(:key_F7),
            # button label
            _("C&onfigure Template")
          )
        )
        UI.ChangeWidget(Id(:templ_pb), :Enabled, items != [])

        nil
      end

      contents = HBox(
        HSpacing(1.5),
        VBox(
          VSpacing(0.5),
          HBox(
            ReplacePoint(Id(:rp_modnames), Empty())
          ),
          VSpacing(0.5),
          Table(
            Id(:table),
            Opt(:notify),
            Header(
              # table header 1/2
              _("Attribute"),
              # table header 2/2
              _("Value")
            ),
            Ops.get_list(modules_attrs_items, current_cn, [])
          ),
          HBox(
            PushButton(Id(:edit), Opt(:key_F4), Label.EditButton),
            HStretch(),
            ReplacePoint(Id(:rp_templs), Empty())
          ),
          VSpacing(0.5)
        ),
        HSpacing(1.5)
      )

      # dialog label
      Wizard.SetContentsButtons(
        _("Module Configuration"),
        contents,
        help_text,
        Label.CancelButton,
        Label.OKButton
      )
      Wizard.HideAbortButton

      if Ops.greater_than(
          Builtins.size(Ops.get_list(modules_attrs_items, current_cn, [])),
          0
        )
        UI.SetFocus(Id(:table))
      end
      replace_templates_items.call
      replace_module_names.call

      # result could be symbol or string
      result = nil
      while true
        result = UI.UserInput
        attr = Convert.to_string(UI.QueryWidget(Id(:table), :CurrentItem))

        # check the correctness of entry
        if Builtins.contains(
            Ops.get_list(modules, [current_dn, "suseDefaultTemplate"], []),
            result
          ) ||
            result == :next ||
            result == :modules 
          Builtins.foreach(
            Ops.get_list(modules, [current_dn, "objectClass"], [])
          ) { |oc| Builtins.foreach(Ldap.GetRequiredAttributes(oc)) do |attr2|
            val = Ops.get(modules, [current_dn, attr2])
            if val == nil || val == [] || val == ""
              #error popup, %1 is attribute name
              Popup.Error(
                Builtins.sformat(
                  _("The \"%1\" attribute is mandatory.\nEnter a value."),
                  attr2
                )
              )
              UI.SetFocus(Id(:table))
              result = :notnext
              next
            end
          end }
        end
        # change the focus to new module
        if result == :modules
          current_cn = Convert.to_string(UI.QueryWidget(Id(:modules), :Value))
          current_dn = get_dn(current_cn)
          if !Builtins.haskey(modules, current_dn)
            current_dn = Builtins.tolower(current_dn)
          end
          UI.ChangeWidget(
            Id(:table),
            :Items,
            Ops.get_list(modules_attrs_items, current_cn, [])
          )
          replace_templates_items.call
        end

        # module attribute modification
        if result == :edit || result == :table
          next if attr == nil
          value = Ops.get_list(modules, [current_dn, attr], [])
          offer = []
          conflicts = []
          conflicts = deep_copy(names) if attr == "cn"
          if Builtins.tolower(attr) == "susedefaulttemplate"
            offer = deep_copy(templates_dns)
          elsif Builtins.tolower(attr) == "susepasswordhash"
            offer = deep_copy(Ldap.hash_schemas)
          end

          value = LdapPopup.EditAttribute(
            {
              "attr"      => attr,
              "value"     => value,
              "conflicts" => conflicts,
              "single"    => Ldap.SingleValued(attr) || attr == "cn",
              "offer"     => offer,
              "browse" =>
                # TODO function, that checks if value should be DN
                Builtins.tolower(attr) == "susedefaultbase" ||
                  Builtins.tolower(attr) == "susedefaulttemplate"
            }
          )

          if value == Ops.get_list(modules, [current_dn, attr], []) #nothing was changed
            next
          end
          Ops.set(modules, [current_dn, attr], value)
          Ops.set(
            modules_attrs_items,
            current_cn,
            create_attrs_items.call(current_cn)
          )
          UI.ChangeWidget(
            Id(:table),
            :Items,
            Ops.get_list(modules_attrs_items, current_cn, [])
          )
          UI.ChangeWidget(Id(:table), :CurrentItem, attr)
          if attr == "cn" && value != []
            cn = Ops.get(value, 0, current_cn)
            Ops.set(
              modules_attrs_items,
              cn,
              Ops.get_list(modules_attrs_items, current_cn, [])
            )
            modules_attrs_items = Builtins.remove(
              modules_attrs_items,
              current_cn
            )
            if Ops.get_string(modules, [current_dn, "modified"], "") != "added" &&
                Ops.get_string(modules, [current_dn, "modified"], "") != "renamed"
              Ops.set(modules, [current_dn, "modified"], "renamed")
              Ops.set(modules, [current_dn, "old_dn"], current_dn)
            end
            Ops.set(modules, get_dn(cn), Ops.get(modules, current_dn, {}))
            if Builtins.tolower(get_dn(cn)) != Builtins.tolower(current_dn)
              modules = Builtins.remove(modules, current_dn)
            end
            names = Builtins.filter(names) { |n| n != current_cn }
            names = Builtins.add(names, cn)
            current_cn = cn
            current_dn = get_dn(cn)
            replace_module_names.call
          end
          if Builtins.tolower(attr) == "susedefaulttemplate"
            replace_templates_items.call
          end
        end
        # configure template
        if result == :templ_pb
          template_dn = Ops.get_string(
            modules,
            [current_dn, "suseDefaultTemplate", 0],
            ""
          )
          Ldap.current_template_dn = template_dn
          template = Builtins.eval(Ops.get(templates, template_dn, {}))
          # template not loaded, check DN:
          if template == {}
            template = Ldap.CheckTemplateDN(template_dn)
            if template == nil
              next
            elsif template == {}
              next if !Ldap.ParentExists(template_dn)
              template = Ldap.CreateTemplate(
                get_cn(template_dn),
                Ops.get_list(modules, [current_dn, "objectClass"], [])
              )
            end
            templates_dns = Builtins.add(templates_dns, template_dn)
          end
          Ops.set(templates, template_dn, TemplateConfigurationDialog(template))
          # check for template renaming
          if Ops.get_list(templates, [template_dn, "cn"], []) !=
              Ops.get_list(template, "cn", [])
            cn = get_string(Ops.get(templates, template_dn, {}), "cn")
            new_dn = get_new_dn(cn, template_dn)

            Ops.set(templates, new_dn, Ops.get(templates, template_dn, {}))
            if new_dn != template_dn
              templates = Builtins.remove(templates, template_dn)
            end
            if Ops.get_string(templates, [new_dn, "modified"], "") != "added"
              Ops.set(templates, [new_dn, "modified"], "renamed")
              Ops.set(templates, [new_dn, "old_dn"], template_dn)
            end
            templates_dns = Builtins.filter(templates_dns) do |dn|
              dn != template_dn
            end
            templates_dns = Builtins.add(templates_dns, new_dn)
            # update list of templates
            Ops.set(
              modules,
              [current_dn, "suseDefaultTemplate"],
              Builtins.maplist(
                Ops.get_list(modules, [current_dn, "suseDefaultTemplate"], [])
              ) do |dn|
                next new_dn if dn == template_dn
                dn
              end
            )
            Ops.set(
              modules_attrs_items,
              current_cn,
              create_attrs_items.call(current_cn)
            )
            UI.ChangeWidget(
              Id(:table),
              :Items,
              Ops.get_list(modules_attrs_items, current_cn, [])
            )
            replace_templates_items.call
          end
          UI.SetFocus(Id(:table))
        end
        if result == :next
          Ldap.current_module_dn = current_dn
          # save the edited values to global map...
          Ldap.CommitConfigModules(modules)
          # commit templates here!
          Ldap.CommitTemplates(templates)
          break
        end
        result = :not_next if result == :cancel && ReallyAbort() != :abort
        break if result == :back || result == :cancel
      end

      Convert.to_symbol(result)
    end
  end
end
