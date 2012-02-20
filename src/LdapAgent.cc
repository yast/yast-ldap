/* ------------------------------------------------------------------------------
 * Copyright (c) 2006-2012 Novell, Inc. All Rights Reserved.
 *
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of version 2 of the GNU General Public License as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, contact Novell, Inc.
 *
 * To contact Novell about this file by physical or electronic mail, you may find
 * current contact information at www.novell.com.
 * ------------------------------------------------------------------------------
 */

/* LdapAgent.cc
 *
 * An agent for reading the ldap configuration file.
 *
 * Authors: Jiri Suchomel <jsuchome@suse.cz>
 *
 * $Id$
 */

#include "LdapAgent.h"
#include <ctype.h>

#define PC(n)       (path->component_str(n))

// convert string to lowercase
string tolower (string in)
{
    string::iterator i;
    for (i = in.begin(); i != in.end(); i++ ) {
	(*i) = tolower (*i);
    }
    return in;
}

/**
 * add blanks to uid/gid entry in table 
 * (for the use of users module)
 */
YCPString addBlanks (int uid)
{
    string s = YCPInteger(uid)->toString();
    int missing = MAX_LENGTH_ID - s.length();
    
    if (missing > 0) {
	for (int i = 0; i < missing; i++) {
	    s = " " + s;
	}
    }
    return YCPString(s);    
}

/**
 * Constructor
 */
LdapAgent::LdapAgent() : SCRAgent()
{
    schema		= NULL;
    ldap		= NULL;
    cons		= NULL;
    ldap_initialized	= false;
    tls_error		= false;
}

/**
 * Destructor
 */
LdapAgent::~LdapAgent()
{
    if (ldap) {
	ldap->unbind();
	delete ldap;
    }
    if (cons) {
	delete cons;
    }
    if (schema) {
	delete schema;
    }
}

/*
 * search the map for value of given key; both key and value have to be strings
 */
string LdapAgent::getValue (const YCPMap map, const string key)
{
    if (!map->value(YCPString(key)).isNull()
	&& map->value(YCPString(key))->isString())
	return map->value(YCPString(key))->asString()->value();
    else
	return "";
}

/**
 * Search the map for value of given key
 * @param map YCP Map to look in
 * @param key key we are looking for
 * @param deflt the default value to be returned if key is not found
 */
int LdapAgent::getIntValue (const YCPMap map, const string key, int deflt)
{
    if (!map->value(YCPString(key)).isNull() && map->value(YCPString(key))->isInteger()) {
	return map->value(YCPString(key))->asInteger()->value(); 
    }
    else if (!map->value(YCPString(key)).isNull() &&
	     map->value(YCPString(key))->isString()) {
	YCPInteger i (map->value(YCPString(key))->asString()->value().c_str());
	return i->value();
    }
    return deflt;
}

/*
 * Search the map for value of given key;
 * key is string and value is boolean
 */
bool LdapAgent::getBoolValue (const YCPMap map, const string key)
{
    if (!map->value(YCPString(key)).isNull() && map->value(YCPString(key))->isBoolean())
	return map->value(YCPString(key))->asBoolean()->value(); 
    else {
	return getIntValue (map, key, 0) ? true : false;
    }
}

/*
 * Search the map for value of given key;
 * key is string and value is YCPList
 */
YCPList LdapAgent::getListValue (const YCPMap map, const string key)
{
    if (!map->value(YCPString(key)).isNull() && map->value(YCPString(key))->isList())
	return map->value(YCPString(key))->asList(); 
    else
	return YCPList();
}

/**
 * creates YCPMap describing object returned as a part of LDAP search command
 * @param single_values if true, return string when argument has only one value
 */
YCPMap LdapAgent::getSearchedEntry (LDAPEntry *entry, bool single_values)
{
    YCPMap ret;	
    const LDAPAttributeList *al= entry->getAttributes();
    // go through attributes of current entry
    for (LDAPAttributeList::const_iterator i=al->begin(); i!=al->end(); i++) {
	YCPValue value = YCPString ("");
	// get the values of current attribute:
	const StringList sl = i->getValues();
	YCPList list = stringlist2ycplist (sl);

	string key = i->getName();
	// list of binary values
	if (key.find (";binary") != string::npos) {
	    BerValue **val = i->getBerValues();
	    YCPList listvalue;
	    for (int j=0; j < i->getNumValues (); j++) {
		BerValue *one_val = val[j];
		listvalue->add (YCPByteblock ((const unsigned char*) one_val->bv_val, one_val->bv_len));
	    }
	    if (single_values && i->getNumValues () == 1) {
		value	= listvalue->value(0);
	    }
	    else {
		value = listvalue;
	    }
	    ber_bvecfree(val);
	}
	// -------------------------------------------------------------------
	else if (single_values && sl.size() == 1)
	    value = YCPString (*(sl.begin()));
	else
	    value = YCPList (list);

	ret->add (YCPString (key), YCPValue(value));
    }
    return ret;
}

/**
 * searches for one object and gets all his non-empty attributes
 * @param dn object's dn
 * @return map of type $[ attr_name: [] ]
 */
YCPMap LdapAgent::getObjectAttributes (string dn)
{
    YCPMap ret;
    LDAPSearchResults* entries = NULL;
    try {
	StringList attrs;
	attrs.add ("*");
	attrs.add ("+");
	entries = ldap->search (dn, 0, "objectClass=*", attrs, true);
    }
    catch  (LDAPException e) {
        debug_exception (e, "searching for attributes (with dn=" + dn + ")");
	return ret;
    }
    // go throught result and generate return value
    if (entries != 0) {
	LDAPEntry* entry = entries->getNext();
	if (entry != 0) {
	    ret = getSearchedEntry (entry, false);
	}
	delete entry;
    }
    
    return ret;
}


/**
 * Return YCP of group, given as LDAP object
 * @param entry LDAP object of the group [item of search result]
 * @param member_attribute name of attribute with members ("member"/"uniqueMember")
 */
YCPMap LdapAgent::getGroupEntry (LDAPEntry *entry, string member_attribute)
{
    YCPMap ret;	
    const LDAPAttributeList *al= entry->getAttributes();
    string member_attr	= tolower (member_attribute);
    // go through attributes of current entry
    for (LDAPAttributeList::const_iterator i=al->begin(); i!=al->end(); i++) {
	YCPValue value = YCPString ("");
	string key = i->getName();
	string userlist;
	
	// get the values of current attribute:
	const StringList sl = i->getValues();
	YCPList list = stringlist2ycplist (sl);
	
	if ((sl.size() > 1 || tolower (key) == member_attr) && key != "cn")
	{
	    value = YCPList (list);
	}
	else
	{
	    string val = *(sl.begin());
	    if ( tolower (key) == "gidnumber" )
		value = YCPInteger (atoi (val.c_str()));
	    else
		value = YCPString (val);
	}

	ret->add(YCPString (key), YCPValue(value));
    }
    // for the need of yast2-users
    ret->add (YCPString ("type"), YCPString ("ldap"));
    return ret;
}


/**
 * Return YCP of user, given as LDAP object
 * @param entry LDAP object of the user [item of search result]
 */
YCPMap LdapAgent::getUserEntry (LDAPEntry *entry)
{
    YCPMap ret;
	
    const LDAPAttributeList *al= entry->getAttributes();
    // go through attributes of current entry
    for (LDAPAttributeList::const_iterator i=al->begin(); i!=al->end(); i++) {
	YCPValue value = YCPString ("");
	string key = i->getName();
	string userlist;
	
	// get the values of current attribute:
	const StringList sl = i->getValues();
	YCPList list = stringlist2ycplist (sl);
	
	// list of binary values
	if (key.find (";binary") != string::npos) {
	    BerValue **val = i->getBerValues();
	    YCPList listvalue;
	    for (int j=0; j < i->getNumValues (); j++) {
		BerValue *one_val = val[j];
		listvalue->add (YCPByteblock ((const unsigned char*) one_val->bv_val, one_val->bv_len));
	    }
	    value = listvalue;
	    ber_bvecfree(val);
	}
	// list of strings
	else if (sl.size() > 1 && tolower (key) != "uid") {
	    value = YCPList (list);
	}
	// string or integer
	else {
	    string val = *(sl.begin());
	    if ( tolower (key) == "gidnumber" || tolower (key) == "uidnumber")
		value = YCPInteger (atoi (val.c_str()));
	    else
		value = YCPString (val);
	}
	ret->add(YCPString (key), YCPValue(value));
    }
    
    // for the need of yast2-users
    ret->add (YCPString ("type"), YCPString ("ldap"));
    if (ret->value (YCPString("userPassword")).isNull()) {
	ret->add (YCPString ("userPassword"), YCPString ("x"));
    }
    return ret;
}

/**
 * converts YCPList to StringList object
 */
StringList LdapAgent::ycplist2stringlist (YCPList l)
{
    StringList sl;
    for (int i=0; i < l->size(); i++) {
	if (l.value(i)->isInteger()) {
	    sl.add (l->value(i)->toString());
	}
	else if (l.value(i)->isString()) {
	    sl.add (l->value(i)->asString()->value());
	}
    }
    return sl;
}

/**
 * converts StringList object to YCPList value
 */
YCPList LdapAgent::stringlist2ycplist (StringList sl)
{
    YCPList l;
    for (StringList::const_iterator n = sl.begin(); n != sl.end();n++){
	l->add (YCPString (*n));
    }
    return l;
}

/**
 * converts StringList object to YCPList value + each item is lowercased
 */
YCPList LdapAgent::stringlist2ycplist_low (StringList sl)
{
    YCPList l;
    for (StringList::const_iterator n = sl.begin(); n != sl.end();n++){
	l->add (YCPString (tolower (*n)));
    }
    return l;
}

/**
 * creates attributes for new LDAP object and fills their values 
 */
void LdapAgent::generate_attr_list (LDAPAttributeList* attrs, YCPMap map)
{
    for (YCPMapIterator i = map->begin(); i != map->end(); i++) {
	if (i.key()->isString()) {
	    string key = i.key()->asString()->value();
	    // add a new attribute and its value to entry
	    LDAPAttribute new_attr;
	    new_attr.setName (i.key()->asString()->value());
	    if (i.value()->isString()) {
		if (i.value()->asString()->value() == "")
		    continue;
		new_attr.addValue (i.value()->asString()->value());
	    }
	    else if (i.value()->isInteger()) {
		new_attr.addValue (i.value()->toString());
	    }
	    else if (i.value()->isByteblock ()) {
		YCPByteblock data = i.value()->asByteblock();

		BerValue *val = (BerValue*) malloc(sizeof(BerValue));

		val->bv_len = data->size();
		val->bv_val = (char*) malloc (sizeof(char)*(data->size()+1));
    
		memcpy (val->bv_val, data->value(), data->size());

		new_attr.addValue (val);
		ber_bvfree (val);
	    }
	    else if (i.value()->isList()) {
		if (i.value()->asList()->isEmpty())
		    continue;
		// list of binary values...
		if (key.find (";binary") != string::npos) {

		    for (int j=0; j < i.value()->asList()->size(); j++) {
			YCPByteblock data = i.value()->asList()->value(j)->asByteblock();
			BerValue *val = (BerValue*) malloc(sizeof(BerValue));

			val->bv_len = data->size();
			val->bv_val = (char*) malloc (sizeof(char)*(data->size()+1));
			memcpy (val->bv_val, data->value(), data->size());

			new_attr.addValue (val);
		    	ber_bvfree (val);
		    }
		}
		else {
		    // list of strings/integers
		    new_attr.setValues(ycplist2stringlist(i.value()->asList()));
		}
	    }
	    else continue;
	    attrs->addAttribute (new_attr);
	}
    }
}
		
/**
 * creates list of modifications for LDAP object
 * for removing attribute, give it empty value
 */
void LdapAgent::generate_mod_list (LDAPModList* modlist, YCPMap map, YCPValue attrs)
{
    for (YCPMapIterator i = map->begin(); i != map->end(); i++) {
	if (i.key()->isString()) {
	    string key = i.key()->asString()->value();
	    LDAPAttribute attr (key);
	    LDAPModification::mod_op op = LDAPModification::OP_REPLACE;
	    attr.setName (key);
	    bool present = true;
	    if (attrs->isMap()) {
		// check if attribute is present
		present = !attrs->asMap()->value(YCPString (key)).isNull();
	    }
	    if (i.value()->isString() || i.value()->isInteger()) {
		string val;
		if (i.value()->isInteger()) {
		    val = i.value()->toString();
		}
		else {
		    val = i.value()->asString()->value();
		}
		if (val == "") {
		    if (!present) {
			y2warning ("No such attribute '%s'", key.c_str());
			continue;
		    }
		    op = LDAPModification::OP_DELETE;
		}
		else
		    attr.addValue (val);
	    }
	    else if (i.value()->isList()) {
		if (i.value()->asList()->isEmpty()) {
		    if (!present) {
			y2warning ("No such attribute '%s'", key.c_str());
			continue;
		    }
		    op = LDAPModification::OP_DELETE;
		}
		// list of binary values...
		else if (key.find (";binary") != string::npos) {

		    for (int j=0; j < i.value()->asList()->size(); j++) {
			YCPByteblock data = i.value()->asList()->value(j)->asByteblock();
			BerValue *val = (BerValue*) malloc(sizeof(BerValue));

			val->bv_len = data->size();
			val->bv_val = (char*) malloc (sizeof(char)*(data->size()+1));
			memcpy (val->bv_val, data->value(), data->size());

			attr.addValue (val);
		    	ber_bvfree (val);
		    }
		}
		// list of strings
		else {
		    attr.setValues (ycplist2stringlist (i.value()->asList()));
		}
	    }
	    else if (i.value()->isByteblock ()) {
		YCPByteblock data = i.value()->asByteblock();

		BerValue *val = (BerValue*) malloc(sizeof(BerValue));

		val->bv_len = data->size();
		val->bv_val = (char*) malloc (sizeof(char)*(data->size()+1));
    
		memcpy (val->bv_val, data->value(), data->size());

		attr.addValue (val);
		ber_bvfree (val);
	    }
	    else continue;
	    modlist->addModification (LDAPModification (attr, op));
	}
    }
}

void LdapAgent::debug_exception (LDAPException e, string action)
{
    ldap_error = e.getResultMsg();
    ldap_error_code = e.getResultCode();
    y2error ("ldap error while %s (%i): %s", action.c_str(), ldap_error_code,
	    ldap_error.c_str());
    if (e.getServerMsg() != "") {
	y2error ("additional info: %s", e.getServerMsg().c_str());
	server_error = e.getServerMsg();
    }
}

// print the debug information about caught Referral Exception
void LdapAgent::debug_referral (LDAPReferralException e, string action)
{
    const LDAPUrlList urls = e.getUrls ();
    y2milestone ("caught referral; size of url list: %zi", urls.size ());
    for (LDAPUrlList::const_iterator i=urls.begin(); i!=urls.end(); i++) {
	y2milestone ("url: %s", i->getURLString ().c_str());
    }
}

/**
 *  Adapt TLS Settings of existing LDAP connection
 *  args is argument map got from YCP call
 *  tls is string, values are "yes" and "try"
 */
void LdapAgent::set_tls_options (YCPMap args, string set_tls)
{
    string cacertfile	= getValue (args, "cacertfile");
    string cacertdir	= getValue (args, "cacertdir");
    string require      = getValue (args, "require_cert");

    TlsOptions tls;
    if (cacertfile != "") {
	tls.setOption (TlsOptions::CACERTFILE, cacertfile);
    }
    if (cacertdir != "") {
	tls.setOption (TlsOptions::CACERTDIR, cacertdir);
    }

    if (set_tls == "yes") {
        if (require == "never") {
	  tls.setOption (TlsOptions::REQUIRE_CERT, TlsOptions::NEVER);
        }
        else {
	  tls.setOption (TlsOptions::REQUIRE_CERT, TlsOptions::DEMAND);
        }
    }
    if (set_tls == "try") {
	tls.setOption (TlsOptions::REQUIRE_CERT, TlsOptions::TRY);
    }
}


/**
 * Dir
 */
YCPList LdapAgent::Dir(const YCPPath& path)
{
    y2error("Wrong path '%s' in Read().", path->toString().c_str());
    return YCPNull();
}

/**
 * Read
 */
YCPValue LdapAgent::Read(const YCPPath &path, const YCPValue& arg, const YCPValue& opt) {

    y2debug ("path in Read: '%s'.", path->toString().c_str());
    YCPValue ret = YCPVoid();
	
    YCPMap argmap;
    if (!arg.isNull() && arg->isMap())
    	argmap = arg->asMap();
    if (!ldap_initialized && PC(0) != "error") {
	y2error ("Ldap not initialized: use Execute(.ldap) first!");
	ldap_error = "init";
	return YCPVoid();
    }
	
    if (path->length() == 1) {

	/**
	 * error: Read(.ldap.error) -> returns last error message
	 */
	if (PC(0) == "error") {
	    YCPMap retmap;
	    retmap->add (YCPString ("msg"), YCPString (ldap_error));
	    retmap->add (YCPString ("server_msg"), YCPString (server_error));
	    retmap->add (YCPString ("code"), YCPInteger (ldap_error_code));
	    retmap->add (YCPString ("tls_error"), YCPBoolean (tls_error));
	    ldap_error = "";
	    server_error = "";
	    ldap_error_code = 0;
	    tls_error	= false;
	    return retmap;
	}

	/**
	 * generic LDAP search command
	 * Read(.ldap.search, <search_map>) -> result list/map of objects
	 * (return value depends on value of "return_map" parameter
	 */
	else if (PC(0) == "search") {
	    string base_dn	= getValue (argmap, "base_dn");
	    string filter	= getValue (argmap, "filter");
	    if (filter == "") {
		filter = "objectClass=*";
	    }
	    int scope		= getIntValue (argmap, "scope", 0);
	    bool attrsOnly	= getBoolValue (argmap, "attrsOnly");
	    // when true, return map of type $[ dn: object ], not the list
	    // of objects (default is false = lists)
   	    bool return_map	= getBoolValue (argmap, "map");
	    // when true, one-item values are returned as string, not
	    // as list with one value (default is false = always list)
   	    bool single_values	= getBoolValue (argmap, "single_values");
	    // when true, only list of DN's will be returned
	    bool dn_only	= getBoolValue (argmap, "dn_only");
	    // when true, no error message is written when object was not found
	    // (empty list/map is returned)
	    bool not_found_ok	= getBoolValue (argmap, "not_found_ok");
	    // when true, "dn" key is included in result map of each object
	    bool include_dn	=  getBoolValue (argmap, "include_dn");
 
	    StringList attrs = ycplist2stringlist(getListValue(argmap,"attrs"));
			
	    y2debug ("(search call) base:'%s', filter:'%s', scope:'%i'",
		    base_dn.c_str(), filter.c_str(), scope);
	    // do the search call
	    LDAPSearchResults* entries = NULL;
	    try {
		entries = ldap->search (
		    base_dn, scope, filter, attrs, attrsOnly, cons);
	    }
	    catch  (LDAPException e) {
		if (not_found_ok && e.getResultCode() == 32)
		{
		    y2debug ("object not found");
		    if (return_map) return YCPMap();
		    else	    return YCPList();
		}
		else
		{
		    debug_exception (e, "searching for " + base_dn);
		    return ret;
		}
            }

	    // return value is list or map of entries
	    YCPList retlist;
	    YCPMap retmap;

	    // go throught result and generate return value
	    if (entries != 0) {
		LDAPEntry* entry = new LDAPEntry();
		bool ok = true;
		while (ok) {
		    try {
			entry = entries->getNext();
			if (entry != 0) {
			    string dn	= entry->getDN();
			    y2debug ("dn: %s", entry->getDN().c_str());
			    if (dn_only) {
				retlist->add (YCPString (entry->getDN()));
			    }
			    else {
				YCPMap e =getSearchedEntry(entry,single_values);
				if (include_dn) {
				    e->add (YCPString ("dn"), YCPString (dn));
				}
				if (return_map) {
				    retmap->add (YCPString (entry->getDN()), e);
				}
				else
				    retlist->add (e);
			    }
			}
			else ok = false;
			delete entry;
		    }
		    catch (LDAPReferralException e) {
			debug_referral (e, "going through search result");
		    }
		    catch  (LDAPException e) {
			debug_exception (e, "going through search result");
		    }
		}
            }
	    if (return_map) return retmap;
	    else return retlist;
	}
	/**
	 * get the users map (previously searched by users.search)
	 * Read(.ldap.users) -> map
	 */
	else if (PC(0) == "users") {
	    return users;
	}
	/**
	 * get the groups map (previously searched by users.search)
	 * Read(.ldap.groups) -> map
	 */
	else if (PC(0) == "groups") {
	    return groups;
	}
	else {
	    y2error("Wrong path '%s' in Read().", path->toString().c_str());
	}
    }
    else if (path->length() == 2) {

	/**
	 * get the map of object class with given name
	 * Read(.ldap.schema.oc, $[ "name": name]) -> map
	 */
	if (PC(0) == "schema" && (PC(1) == "object_class" || PC(1) == "oc"))  {

	    if (!schema) {
		y2error ("Schema not read! Use Execute(.ldap.schema) before.");
		return ret;
	    }

	    string name		= getValue (argmap, "name");
	    YCPMap ret;
	    if (name == "") {
		y2error ("'name' attribute missing!");
		return ret;
	    }

	    LDAPObjClass oc = schema->getObjectClassByName (name);
	    if (oc.getName() != "")
	    {
		ret->add (YCPString ("kind"), YCPInteger (oc.getKind()));
		ret->add (YCPString ("oid"), YCPString (oc.getOid()));
		ret->add (YCPString ("desc"), YCPString (oc.getDesc()));
		ret->add (YCPString ("must"), stringlist2ycplist(oc.getMust()));
		ret->add (YCPString ("may"), stringlist2ycplist (oc.getMay()));
		ret->add (YCPString ("sup"), stringlist2ycplist (oc.getSup()));
	    }
	    else {
		y2error ("No such objectclass: '%s'", name.c_str());
		ldap_error = "oc_not_found";
	    }

	    return ret;
	}
	/**
	 * get the map of attribute type with given name
	 * Read(.ldap.schema.at, $[ "name": name]) -> map
	 */
	else if (PC(0) == "schema" && (PC(1)=="attr_types" || PC(1) == "at")) {
	    
	    if (!schema) {
		y2error ("Schema not read! Use Execute(.ldap.schema) first.");
		return ret;
	    }
	    string name		= getValue (argmap, "name");
	    YCPMap ret;
	    if (name == "") {
		y2error ("'name' attribute missing!");
		return ret;
	    }

	    LDAPAttrType at = schema->getAttributeTypeByName (name);
	    if (at.getName() != "")
	    {
		ret->add (YCPString ("oid"), YCPString (at.getOid()));
		ret->add (YCPString ("desc"), YCPString (at.getDesc()));
		ret->add (YCPString ("single"), YCPBoolean (at.isSingle()));
		ret->add (YCPString ("usage"), YCPInteger (at.getUsage()));
	    }
	    else {
		y2error ("No such attributeType: '%s'", name.c_str());
		ldap_error = "at_not_found";
	    }
	    return ret;
	}
	/**
	 * get the mapping of usernames to uid's (used for users module)
	 * DEPRECATED, users_by_name is empty now
	 * Read(.ldap.users.by_name) -> map
	 */
	else if (PC(0) == "users" && PC(1) == "by_name") {
	    return users_by_name;
	}
	/**
	 * get the mapping of uid numbers to user names (used for users module)
	 * Read(.ldap.users.by_uidnumber) -> map
	 */
	else if (PC(0) == "users" && PC(1) == "by_uidnumber") {
	    return users_by_uidnumber;
	}
	/**
	 * get the list of home directories (used for users module)
	 * Read(.ldap.users.homes) -> list of homes
	 */
	else if (PC(0) == "users" && PC(1) == "homes") {
	    return homes;
	}
	/**
	 * get the list of UID's (used for users module)
	 * Read(.ldap.users.uids) -> list
	 */
	else if (PC(0) == "users" && PC(1) == "uids") {
	    return uids;
	}
	/**
	 * get the list of user names (used for users module)
	 * Read(.ldap.users.usernames) -> list
	 */
	else if (PC(0) == "users" && PC(1) == "usernames") {
	    return usernames;
	}
	/**
	 * get the list of user DN's (used for users module)
	 * Read(.ldap.users.userdns) -> list
	 */
	else if (PC(0) == "users" && PC(1) == "userdns") {
	    return userdns;
	}
	/**
	 * get the items for user table (used for users module)
	 * Read(.ldap.users.itemlist) -> list of items
	 */
	else if (PC(0) == "users" && PC(1) == "items") {
	    return user_items;
	}
	/**
	 * get the map of gid's indexed by group names (used for users module)
	 * DEPRECATED, groups_by_name is empty now
	 * Read(.ldap.groups.by_name) -> map
	 */
	else if (PC(0) == "groups" && PC(1) == "by_name") {
	    return groups_by_name;
	}
	/**
	 * get the mapping of gid numbers to group names (used for users module)
	 * Read(.ldap.groups.by_uidnumber) -> map
	 */
	else if (PC(0) == "groups" && PC(1) == "by_gidnumber") {
	    return groups_by_gidnumber;
	}
	/**
	 * get the list of GID's (used for users module)
	 * Read(.ldap.groups.gids) -> list
	 */
	else if (PC(0) == "groups" && PC(1) == "gids") {
	    return gids;
	}
	/**
	 * get the list of group names (used for users module)
	 * Read(.ldap.groups.groupnames) -> list
	 */
	else if (PC(0) == "groups" && PC(1) == "groupnames") {
	    return groupnames;
	}
	/**
	 * get the items for group table (used for users module)
	 * Read(.ldap.groups.itemlist) -> list of items
	 */
	else if (PC(0) == "groups" && PC(1) == "items") {
	    return group_items;
	}
	else {
	    y2error("Wrong path '%s' in Read().", path->toString().c_str());
	}
    }
    else if (path->length() > 2) {

	/**
	 * check if given object class exists in schema
	 * Read(.ldap.schema.oc.check, $[ "name": name]) -> boolean
	 */
	if (PC(0) == "schema" && (PC(1) == "object_class" || PC(1) == "oc") &&
	    PC(2) == "check") {

	    if (!schema) {
		y2error ("Schema not read! Use Execute(.ldap.schema) before.");
		return YCPBoolean (false);
	    }

	    string name		= getValue (argmap, "name");
	    if (name == "") {
		y2error ("'name' attribute missing!");
		return YCPBoolean (false);
	    }
	    LDAPObjClass oc = schema->getObjectClassByName (name);
	    if (oc.getName() != "")
		return YCPBoolean (true);
	    else
		return YCPBoolean (false);
	}
	else {
	    y2error("Wrong path '%s' in Read().", path->toString().c_str());
	}
    }
    else {
	y2error("Wrong path '%s' in Read().", path->toString().c_str());
    }
    return YCPVoid();
}

/**
 * delete children of LDAP entry (code from rhafer)
 */
YCPBoolean LdapAgent::deleteSubTree (string dn) {
    y2debug ("deleting children of '%s'", dn.c_str());
    if (ldap) {
	LDAPSearchResults* res	= 0;
        LDAPEntry* entry	= 0;
        StringList attrs;
        attrs.add ("dn");
        try {
	    // search for object children
            res = ldap->search (dn, LDAPConnection::SEARCH_ONE,
                    "objectClass=*", attrs, true);
            if (!(entry = res->getNext())) {
                delete entry;
                entry=0;
                delete res;
                res=0;
            } else {
                do {
		    deleteSubTree (entry->getDN ());
		    y2debug ("deleting entry:'%s'", entry->getDN().c_str());
		    try {
			ldap->del (entry->getDN());
		    }
		    catch (LDAPException e) {
			debug_exception (e, "deleting entry " + entry->getDN());
			delete entry;
			return YCPBoolean (false);
		    }
                    delete entry;
                    entry = 0;
                } while ((entry=res->getNext()));
            }
        } catch (LDAPException e) {
            delete res;
            delete entry;
	    debug_exception (e, "searching for subtree of " + dn);
	    return YCPBoolean (false);
        }
    }
    return YCPBoolean (true);
}

/**
 * copy the LDAP entry to new place
 * (+ changes DN-constructing attribute, like cn,uid,ou etc.)
 * @param dn DN of original entry
 * @param new_dn new DN (= new place)
 */
YCPBoolean LdapAgent::copyOneEntry (string dn, string new_dn) {

    if (!ldap) {
	ldap_error = "init";
	return YCPBoolean (false);
    }
    y2debug ("copying object %s to %s", dn.c_str(), new_dn.c_str());
    // 1. search for all attributes of current entry
    LDAPSearchResults* entries 	= NULL;
    try {
	// search for object children
        entries = ldap->search (dn, 0);
	LDAPEntry* entry;
	entry	= 0;
	if (entries != 0)
	    entry	= entries->getNext();
        if (entry) {

	    YCPMap e = getSearchedEntry (entry, false);

	    LDAPAttributeList* attrs = new LDAPAttributeList();

	    // change the attribute for creating DN (cn,uid etc.) if necessary
	    string rdn	= new_dn.substr (0, new_dn.find (","));
	    string attr	= rdn.substr (0, rdn.find ("="));

	    string attr_val	= rdn.substr (rdn.find("=")+ 1);
	    YCPValue v = e->value (YCPString (attr));
	    if (v->isList ()) {
		YCPList l	= v->asList();
		if (!l->contains (YCPString (attr_val))) {
		    l->add (YCPString (attr_val));
		    e->add (YCPString (attr), l);
		}
	    }
	    
	    // list of attributes for new entry
	    generate_attr_list (attrs, e);

	    y2debug ("(add call) dn:'%s'", new_dn.c_str());
	    LDAPEntry* entry = new LDAPEntry (new_dn, attrs);
	    try {
		ldap->add (entry);
	    }
	    catch (LDAPException e) {
		debug_exception (e, "adding " + new_dn);
		delete entries;
		return YCPBoolean (false);
	    }
	}
    } catch (LDAPException e) {
        delete entries;
	debug_exception (e, "searching for " + dn);
	return YCPBoolean (false);
    }
    return YCPBoolean (true);
}
 

/**
 * move the entry in LDAP tree with all its children
 * @param dn DN of original entry
 * @param new_dn new DN (= new place)
 * @param parent_dn DN of the new parent of the entry
 */
YCPBoolean LdapAgent::moveWithSubtree (string dn, string new_dn, string parent_dn) {

    YCPBoolean ret = YCPBoolean(true);

    if (!ldap) {
	ldap_error = "init";
	return YCPBoolean (false);
    }
    y2debug ("moving object '%s'", dn.c_str());
    // 1. check if entry has children
    LDAPSearchResults* entries 	= NULL;
    try {
	// search for object children
        entries = ldap->search (dn, 1, "objectClass=*");
	LDAPEntry* entry;
	entry	= 0;
	if (entries != 0)
	    entry	= entries->getNext();
        if (entry) {
	    // 1a has children -> create new entry on the new place
	    ret	= copyOneEntry (dn, new_dn);
	    if (!ret->value ()) {
		delete entries;
		return ret;
	    }

	    // 2. call moveWithSubtree on child entry
	    do {
		// we must generate new dn of child entry
		string child_dn	= entry->getDN();
		string rdn	= child_dn.substr (0, child_dn.find (","));
		child_dn	= rdn + "," + new_dn;

		y2debug ("dn of children object: %s", entry->getDN().c_str());
		ret = moveWithSubtree (entry->getDN(), child_dn, new_dn);
	    }
	    while (ret->value () && (entry = entries->getNext()));

	    if (!ret->value ()) {
		delete entries;
		return ret;
	    }
	    // 3. delete original entry (should have no subtree now)
	    y2debug ("(delete call) dn:'%s'", dn.c_str());
	    try {
		ldap->del (dn);
	    }
	    catch (LDAPException e) {
		debug_exception (e, "deleting entry" + dn);
		return YCPBoolean (false);
	    }
   	}
	else {
	    // 1b no children, call rename
	    string rdn		= new_dn.substr (0, new_dn.find (","));
	    try {
		ldap->rename (dn, rdn, true, parent_dn);
	    }
	    catch (LDAPException e) {
		delete entries;
		debug_exception (e, "renaming " + dn + " to " + new_dn);
		return YCPBoolean (false);
	    }
	}
    } catch (LDAPException e) {
        delete entries;
	debug_exception (e, "searching for subtree of " + dn);
	return YCPBoolean (false);
    }
    return YCPBoolean (true);
}

/**
 * Write
 */
YCPBoolean LdapAgent::Write(const YCPPath &path, const YCPValue& arg,
       const YCPValue& arg2)
{
    y2debug ("path in Write: '%s'.", path->toString().c_str());

    YCPBoolean ret = YCPBoolean(true);
    
    YCPMap argmap, argmap2;
    if (!arg.isNull() && arg->isMap())
	argmap = arg->asMap();
    if (!arg2.isNull() && arg2->isMap())
	argmap2 = arg2->asMap();

    if (!ldap_initialized) {
	y2error ("Ldap not initialized: use Execute(.ldap) first!");
	ldap_error = "init";
	return YCPBoolean (false);
    }

    if (path->length() == 1) {

	/**
	 * generic LDAP add command
	 * Write(.ldap.add, $[ "dn": dn ], <add_map>) -> boolean
	 */
	if (PC(0) == "add") {
	    string dn = getValue (argmap, "dn");
	    if (dn == "") {
		y2error ("Value of DN is missing or invalid !");
		ldap_error = "missing_dn";
		return YCPBoolean (false);
	    }
	    // generate the list of attributes from parameters:
	    LDAPAttributeList* attrs = new LDAPAttributeList();
	    generate_attr_list (attrs, argmap2);

	    y2debug ("(add call) dn:'%s'", dn.c_str());
	    LDAPEntry* entry = new LDAPEntry (dn, attrs);
	    try {
		ldap->add(entry);
	    }
	    catch (LDAPException e) {
		debug_exception (e, "adding " + dn);
		ret = YCPBoolean (false);
	    }
	    delete attrs;
	    return ret;
	}
	/**
	 * generic LDAP modify command
	 * Write(.ldap.modify, <arg_map>, <modify_map>) -> boolean
	 * - modify_map is list of attributes and its values to add or modify.
	 * - To remove some attribute, use empty value ("" or []) for it.
	 * - arg_map has to contain "dn" entry.
	 * - If arg_map contains "rdn" key, object will be renamed using the
	 * value of "rdn" as new Relative Distinguished Name. For moving, use
	 * "newParentDN" value for new parent DN of object.
	 * - "new_dn" new DN of renamed object
	 * - If arg_map contains "check_attrs" key (with true value), there
	 * will be done search for current object's attributes before modify.
	 * When some attribute in modify_map has empty value it will be ignored,
	 * if object currently has not this attribute.
	 * Otherwise ("check_attrs" is false as default), this situation leads
	 * to error message, because non-existent attribute is set for deletion.
	 */
	if (PC(0) == "modify" || PC(0) == "edit") {
	    string dn		= getValue (argmap, "dn");
	    // if true, do the search for existing atributes of modified object
	    bool check_attrs	= getBoolValue (argmap, "check_attrs");
	    if (dn == "") {
		y2error ("Value of DN is missing or invalid !");
		ldap_error = "missing_dn";
		return YCPBoolean (false);
	    }
	    YCPValue attrs = YCPVoid();
	    if (check_attrs) {
		// we must call this before renaming
		attrs = getObjectAttributes (dn);
	    }
	    string new_dn 	= getValue (argmap, "new_dn");
	    string newParentDN	= getValue (argmap, "newParentDN");

	    // check for possible object renaming
   	    if (new_dn != "" && getBoolValue (argmap, "subtree")) {
		ret = moveWithSubtree (dn, new_dn, newParentDN);
	    }
	    else {	
		string rdn	= getValue (argmap, "rdn");
		if (rdn == "" && new_dn != "") {
		    rdn		= new_dn.substr (0, new_dn.find (","));
		}
		if (rdn != "") {
		    bool delOldRDN	= getBoolValue (argmap, "delOldRDN");
		    try {
			ldap->rename (dn, rdn, delOldRDN, newParentDN);
		    }
		    catch (LDAPException e) {
			debug_exception (e, "renaming " + dn + " to " + rdn);
			return YCPBoolean (false);
		    }
		}
	    }
	    if (!ret->value()) {
		// moving with subtree failed
		return YCPBoolean (false);
	    }

	    // now edit changed attributes of the entry
	    // generate the list of modifications from parameters:
	    LDAPModList *modlist = new LDAPModList();
	    generate_mod_list (modlist, argmap2, attrs);

	    if (new_dn != "") {
		dn = new_dn;
	    }
	    y2debug ("(modify call) dn:'%s'", dn.c_str());
	    try {
		ldap->modify (dn, modlist);
	    }
	    catch (LDAPException e) {
		debug_exception (e, "modifying " + dn);
		delete modlist;
		return YCPBoolean (false);
	    }
	    delete modlist;
	    return ret;
	}
	/**
	 * generic LDAP delete command
	 * Write(.ldap.delete, $[ "dn" : dn ]) -> boolean
	 */
	if (PC(0) == "delete") {
	    string dn = getValue (argmap, "dn");
	    if (dn == "") {
		y2error ("Value of DN is missing or invalid !");
		ldap_error = "missing_dn";
		return YCPBoolean (false);
	    }
   	    bool delete_subtree = getBoolValue (argmap, "subtree");
	    if (delete_subtree) {
		ret = deleteSubTree (dn);
	    }
	    if (!ret->value()) {
		return ret;
	    }
	    y2debug ("(delete call) dn:'%s'", dn.c_str());
	    try {
		ldap->del (dn);
	    }
	    catch (LDAPException e) {
		debug_exception (e, "deleting " + dn);
		return YCPBoolean (false);
	    }
	    return ret;
	}
	else {
	   y2error("Wrong path '%s' in Write().", path->toString().c_str());
	}
    }
    else {
    	y2error("Wrong path '%s' in Write().", path->toString().c_str());
    }
    return ret;
}

/**
 * Execute
 */
YCPValue LdapAgent::Execute(const YCPPath &path, const YCPValue& arg,
	const YCPValue& arg2)
{
    y2debug ("path in Execute: '%s'.", path->toString().c_str());
    YCPValue ret = YCPBoolean (true);

    YCPMap argmap;
    if (!arg.isNull() && arg->isMap())
	argmap = arg->asMap();
	
    /**
     * initialization: Execute (.ldap,$[
     * 	"hostname": <host>, "port": <port>, "use_tls": "no"|"yes"|"try" ] )
     */
    if (path->length() == 0) {

	ldap_initialized	= false;

	hostname = getValue (argmap, "hostname");
	if (hostname =="") {
	    y2error ("Missing hostname of LDAPHost, aborting");
	    return YCPBoolean (false);
	}

 	port = getIntValue (argmap, "port", DEFAULT_PORT);

	// TODO how/where to set this?
	cons = new LDAPConstraints;

	try {
	    ldap = new LDAPConnection (hostname, port, cons);
	}
	catch (LDAPException e) {
	    debug_exception (e, "init");
	    delete ldap;
	    ldap	= NULL;
	    y2error ("Error while initializing connection object");
	    return YCPBoolean (false);
	}

	// start TLS if proper parameter is given
	string tls	= getValue (argmap, "use_tls");
	set_tls_options (argmap, tls);

	if (tls == "try" || tls == "yes") {
	    try {
		ldap->start_tls ();
	    }
	    catch  (LDAPException e) {
		// check if starting TLS failed
		debug_exception (e, "starting TLS");
		delete ldap;
		ldap	= NULL;
		// return an error if TLS is required
		if (tls == "yes") {
		    tls_error	= true;
		    return YCPBoolean (false);
		}
		ldap_error = "";
		server_error = "";
		ldap_error_code = 0;
		// "try" -> start again, but without tls
		ldap = new LDAPConnection (hostname, port, cons);
		if (!ldap || !cons)
		{
		    y2error ("Error while initializing connection object");
		    ldap_error 		= "init";
		    return YCPBoolean (false);
		}
	    }
	}
	ldap_initialized = true;
	return YCPBoolean (true);
    }

    if (!ldap_initialized && PC(0) != "ping" && PC(0) != "ppolicy") {
	y2error ("Ldap not initialized: use Execute(.ldap) first!");
	ldap_error = "init";
	return YCPBoolean (false);
    }
	
    if (path->length() == 1) {

	/**
	 * ping: Execute (.ldap.ping, $[ "hostname": <host>, "port": <port> ] )
	 * returns true if server is running
	 */
	if (PC(0) == "ping") {

	    string host_tmp = getValue (argmap, "hostname");
	    if (host_tmp == "") {
		y2error ("Missing hostname of LDAPHost, aborting");
		return YCPBoolean (false);
	    }
	    int port_tmp = getIntValue (argmap, "port", DEFAULT_PORT);

	    LDAPConnection *ldap_tmp = new LDAPConnection (host_tmp, port_tmp);
	    if (!ldap_tmp) {
		delete ldap_tmp;
		ldap_error = "init";
		y2error ("ping: failed to create LDAPConnection object");
		return YCPBoolean (false);
	    }
	    LDAPSearchResults* entries = NULL;
	    try {
		entries = ldap_tmp->search ("");
	    }
	    catch  (LDAPException e) {
		delete ldap_tmp;
		debug_exception (e, "doing the ping");
		return YCPBoolean (false);
            }

	    delete ldap_tmp;
	    return YCPBoolean(true);
	}
	/**
	 * ppolicy: Execute (.ldap.ppolicy, $["hostname": <host>, "port": <port>, "bind_dn": <dn>] )
	 * returns true if server suports Password Policy (feature 301179):
	 *
	 * rhafer: 'To detect if the server does support LDAP Password Policies you can send it a
	 * LDAP Bind Request with the Password Policy Control attached and marked as "critical".
	 * The bind-dn should ether be set to the base-dn of the LDAP Database or a child of it
	 * (the entry itself does not need to exist in the Database). The bind-pw most not be empty
	 * (just some random string is fine) 
	 *  If the server supports Password Policies you'll get back Error Code 49:
	 *  "Invalid credentials". if it does not support Password Policies you'll get Error Code
	 *  53: "Server is unwilling to perform" with the additional message:
	 *  "critical control unavailable in context"'
	 */
	if (PC(0) == "ppolicy") {

	    string host_tmp = getValue (argmap, "hostname");
	    if (host_tmp == "") {
		y2error ("Missing hostname of LDAPHost, aborting");
		return YCPBoolean (false);
	    }
	    int port_tmp = getIntValue (argmap, "port", DEFAULT_PORT);

	    LDAPConnection *ldap_tmp = new LDAPConnection (host_tmp, port_tmp);
	    if (!ldap_tmp) {
		delete ldap_tmp;
		ldap_error = "init";
		y2error ("ppolicy: failed to create LDAPConnection object");
		return YCPBoolean (false);
	    }
	    YCPValue ret = YCPBoolean (true);
	    bind_dn = getValue (argmap, "bind_dn");
			
	    // now add critical Password Policy Control
	    LDAPCtrl ppolicyCtrl ("1.3.6.1.4.1.42.2.27.8.5.1", true);
	    LDAPControlSet cs;
	    cs.add (ppolicyCtrl);
	    LDAPConstraints *cons_tmp	= new LDAPConstraints;
            cons_tmp->setServerControls (&cs);
	    try {
		ldap_tmp->bind (bind_dn, "muhahaha", cons_tmp);
	    }
	    catch (LDAPException e) {
	        int error_code = e.getResultCode();
		string error = e.getResultMsg();
		y2debug ("ldap error (%i): %s", error_code, error.c_str());
		if (e.getServerMsg() != "") {
		    y2debug ("additional info: %s", e.getServerMsg().c_str());
		}
		if (error_code != 49 && error_code != 0)
		    ret	= YCPBoolean (false);
	    }
	    delete ldap_tmp;
	    delete cons_tmp;
	    return ret;
	}	
	/**
	 * bind: Execute(.ldap.bind, $[ "bind_dn": binddn, "bindpw": bindpw] )
	 * for anonymous acess, call bind with empty map
	 */
	else if (PC(0) == "bind") {

	    bind_dn = getValue (argmap, "bind_dn");
	    bind_pw = getValue (argmap, "bind_pw");
			
	    try {
		ldap->bind (bind_dn, bind_pw, cons);
	    }
	    catch (LDAPException e) {
		debug_exception (e, "binding with " + bind_dn);
		return YCPBoolean (false);
	    }
	    return YCPBoolean(true);
	}
	/**
	 * unbind: Execute(.ldap.unbind)
	 */
	else if (PC(0) == "unbind") {
	    ldap->unbind();
	    return YCPBoolean(true);
	}
	/** 
	 * close the connection, delete object
	 */
	else if (PC(0) == "close") {
	    ldap->unbind();
	    delete ldap;
	    ldap		= NULL;
	    ldap_initialized	= false;
	    return YCPBoolean(true);
	}
	/**
	 * Initialize schema: read and parse it
	 */
	else if (PC(0) == "schema") {
	    string schema_dn	= getValue (argmap, "schema_dn");
	    schema = new LDAPSchema ();

	    StringList sl;
	    sl.add ("objectclasses");
	    sl.add ("attributetypes");
	    LDAPSearchResults* entries = NULL;
	    try {
		entries = ldap->search (schema_dn, 0, "objectClass=*", sl);
	    }
	    catch  (LDAPException e) {
		debug_exception (e, "searching for " + schema_dn);
		return YCPBoolean (false);
            }
	    // go throught result and fill schema object
	    if (entries != 0) {
		LDAPEntry* entry = entries->getNext();
		if (entry != 0) {
		    const LDAPAttributeList *al= entry->getAttributes();
		    schema->setObjectClasses (al->getAttributeByName
			   ("objectclasses")->getValues());
		    schema->setAttributeTypes (al->getAttributeByName
			   ("attributetypes")->getValues());
		}
		delete entry;
	    }
	    return YCPBoolean (true);
	}
	else if (PC(0) == "start_tls") {
	    
	    set_tls_options (argmap, "yes");
	    try {
		ldap->start_tls ();
	    }
	    catch  (LDAPException e) {
		debug_exception (e, "starting TLS");
		tls_error	= true;
		return YCPBoolean (false);
	    }
	    return YCPBoolean(true);
	}

	else {
	   y2error("Wrong path '%s' in Execute().", path->toString().c_str());
	}
    }
    else if (path->length() == 2) {

	/**
	 * LDAP users search command
	 * Read(.ldap.users.search, <search_map>) -> result list
	 * (more special work is done than in generic search)
	 */
	if (PC(0) == "users" && PC(1) == "search") {
	    string user_base	= getValue (argmap, "user_base");
	    string group_base	= getValue (argmap, "group_base");
	    string user_filter	= getValue (argmap, "user_filter");
	    string group_filter	= getValue (argmap, "group_filter");
	    // which attribute have groups for list of members
	    string member_attribute	=
		getValue (argmap, "member_attribute");
	    if (member_attribute == "")
		member_attribute	= "uniqueMember";

	    int user_scope	= getIntValue (argmap, "user_scope", 2);
	    int group_scope	= getIntValue (argmap, "group_scope", 2);
	    bool itemlists	= getBoolValue (argmap, "itemlists");
	    StringList user_attrs = ycplist2stringlist (
		    getListValue(argmap, "user_attrs"));
   	    StringList group_attrs = ycplist2stringlist (
		    getListValue(argmap, "group_attrs"));

	    // for each user, store groups that user belongs to:
	    map <string, YCPMap > grouplists;
	    // for each user item, store groups as string:
	    map <string, string > s_grouplists;
	    // for each group, store users having this group as default:
	    map <int, YCPMap> more_usersmap;

	    // when true, no error message is written when object was not found
	    bool not_found_ok	= true;
   
	    // first, search for groups
	    LDAPSearchResults* entries = NULL;
	    try {
		entries = ldap->search (group_base, group_scope, group_filter,
		       group_attrs, false, cons);
	    }
	    catch  (LDAPException e) {
		if (not_found_ok && e.getResultCode() == 32) {
		    y2warning ("groups not found");
		}
		else {
		    debug_exception (e, "searching for " + group_base);
		    return YCPBoolean (false);
		}
            }

	    // initialize the maps/lists to be filled
	    users = YCPMap();
	    users_by_name = YCPMap();
	    users_by_uidnumber = YCPMap();
	    groups = YCPMap();
	    groups_by_name = YCPMap();
	    groups_by_gidnumber = YCPMap();

	    user_items	= YCPMap();
	    uids	= YCPMap();
	    homes	= YCPMap();
	    usernames	= YCPMap();
	    userdns	= YCPMap();
	    group_items = YCPMap();
	    groupnames	= YCPMap();
	    gids	= YCPMap();

	    // now generate group map (to use with users)
	    if (entries != 0) {
	    
	    LDAPEntry* entry = new LDAPEntry();
	    bool ok = true;
	    while (ok) {
	      try {
		entry = entries->getNext();
		if (entry != 0) {
		    YCPMap group = getGroupEntry (entry, member_attribute);
		    group->add (YCPString("dn"), YCPString(entry->getDN()));
		    int gid = getIntValue (group, "gidNumber", -1);
		    if (gid == -1) {
			y2warning("Group '%s' has no gidNumber?",
			    entry->getDN().c_str());
			continue;
		    }
		    string groupname = getValue (group, "cn");
		    
		    // go through userlist of this group
		    YCPList ul = getListValue (group, member_attribute);
		    string s_ul;
		    YCPMap usermap;
		    for (int i=0; i < ul->size(); i++) {
			// For each user in userlist add this group to the
			// map of type "user->his groups".
			string udn = ul->value(i)->asString()->value();
			(grouplists[udn])->add (YCPString (groupname), YCPInteger (1));
			if (s_grouplists.find (udn) != s_grouplists.end())
			    s_grouplists [udn] += ",";
			s_grouplists[udn] += groupname;

			if (itemlists) {
			    string rest = udn.substr (udn.find ("=") + 1);
			    string user = rest.substr (0, rest.find (","));
			    if (i>0) s_ul += ",";
			    s_ul += user;
			}
			usermap->add (YCPString (udn), YCPInteger (1));
		    }
		    group->add (YCPString (member_attribute), usermap);
		    // change list of users to string (need only for itemlist)
		    if (itemlists) {
			group->add (YCPString ("s_userlist"), YCPString(s_ul));
		    }
		    group->add (YCPString ("more_users"), YCPMap ());
		    // ------- finally add new item to return maps
		    groups->add (YCPString (groupname), group);
		    if (groups_by_gidnumber->value(YCPInteger(gid)).isNull()) {
			groups_by_gidnumber->add (YCPInteger (gid), YCPMap ());
		    }
		    YCPMap gids_map =
		       groups_by_gidnumber->value (YCPInteger(gid))->asMap();
		    gids_map->add (YCPString (groupname), YCPInteger(1));
		    groups_by_gidnumber->add (YCPInteger (gid), gids_map);

		    groupnames->add (YCPString (groupname), YCPInteger(1));
		    gids->add (YCPInteger (gid), YCPInteger(1));
		}
		else ok = false;
		delete entry;
	      }
	      catch (LDAPReferralException e) {
		debug_referral (e, "going through group search result");
	      }
	      catch  (LDAPException e) {
		debug_exception (e, "going through group search result");
	      }
	    }
            }
	    
	    // search for users
	    entries = NULL;
	    try {
		entries = ldap->search (user_base, user_scope, user_filter,
		       user_attrs, false, cons);
	    }
	    catch  (LDAPException e) {
		if (not_found_ok && e.getResultCode() == 32) {
		    y2warning ("users not found");
		}
		else {
		    debug_exception (e, "searching for " + user_base);
		    return YCPBoolean (false);
		}
            }

	    // go through user entries and generate maps
	    if (entries != 0) {
	    
	    LDAPEntry* entry = new LDAPEntry();
	    bool ok = true;
	    while (ok) {
	      try {
		entry = entries->getNext();
		if (entry != 0) {
		    // get the map of user
		    YCPMap user = getUserEntry (entry);
		    string dn = entry->getDN();
		    user->add (YCPString("dn"), YCPString(dn));
		    // check it
		    int uid = getIntValue (user, "uidNumber", -1);
		    if (uid == -1) {
			y2warning("User with dn '%s' has no uidNumber?",
			    dn.c_str());
			continue;
		    }
		    // get the name of default group
		    int gid = getIntValue (user, "gidNumber", -1);
		    string groupname;
		    if (!groups_by_gidnumber->value(YCPInteger(gid)).isNull())
		    {
			YCPMap gmap	= 
			   groups_by_gidnumber->value(YCPInteger(gid))->asMap();
			groupname = gmap->begin().key()->asString()->value();
		    }
		    if (groupname != "")
			user->add (YCPString("groupname"),YCPString(groupname));

		    // get the list of groups user belongs to
		    string username = getValue (user, "uid");
		    // 'grouplist' as string is used to generate table item
		    string grouplist; 
		    if (s_grouplists.find (dn) != s_grouplists.end())
			grouplist = s_grouplists[dn];
		    // and grouplist as map is saved to user map
		    if (grouplists.find (dn) != grouplists.end()) {
			user->add (YCPString ("grouplist"), grouplists[dn]);
		    }
		    else {
			user->add (YCPString ("grouplist"), YCPMap ());
		    }
		    // default group of this user has to know of this user:
		    (more_usersmap [gid])->add (YCPString (username), YCPInteger(1));
		    // generate itemlist
		    if (itemlists) {
			YCPTerm item ("item"), id ("id");
			id->add (YCPString (username));
			item->add (YCPTerm (id));
			item->add (YCPString (username));
			item->add (YCPString (getValue (user, "cn")));
			item->add (addBlanks (uid));
			string all_groups = groupname;
			if (grouplist != "") {
			    if (all_groups != "")
				all_groups += ",";
			    all_groups += grouplist;
			}
			// these 3 dots are for local groups
			if (all_groups != "")
			    all_groups += ",";
			all_groups += "...";
			item->add (YCPString (all_groups));
			user_items->add (YCPString (username), item);
		    }
		    
		    // ------- finally add new item to return maps
		    users->add (YCPString (username), user);
		    // helper structures for faster searching in users module
		    if (users_by_uidnumber->value(YCPInteger(uid)).isNull()) {
			users_by_uidnumber->add (YCPInteger (uid), YCPMap ());
		    }
		    YCPMap uids_map =
			users_by_uidnumber->value (YCPInteger(uid))->asMap();
		    uids_map->add (YCPString (username), YCPInteger(1));
		    users_by_uidnumber->add (YCPInteger (uid), uids_map);

		    uids->add (YCPInteger (uid), YCPInteger(1));
		    usernames->add (YCPString (username), YCPInteger(1));
		    userdns->add (YCPString (dn), YCPInteger(1));
		    string home = getValue (user,"homeDirectory");
		    if (home != "") {
			homes->add (YCPString (home), YCPInteger(1));
		    }
		}
		else ok = false;
		delete entry;
	      }
	      catch (LDAPReferralException e) {
		debug_referral (e, "going through user search result");
	      }
	      catch  (LDAPException e) {
		debug_exception (e, "going through user search result");
	      }
	    }
            }
	    // once again, go through groups and update group maps	    
	    for (YCPMapIterator i = groups->begin(); i != groups->end(); i++) {

		YCPMap group = i.value()->asMap();
		string groupname = i.key()->asString()->value();
		int gid = getIntValue (group, "gidNumber", -1);
		string more_users; // TODO create contents if itemlists
		if (more_usersmap.find (gid) != more_usersmap.end()) {
		    group->add (YCPString ("more_users"), more_usersmap[gid]);
		    // TODO better to add directly while processing users...
		    groups->add (YCPString (groupname), group);
		}
		// generate itemlist if wanted
		if (itemlists) {
		    YCPTerm item ("item"), id ("id");
		    id->add (YCPString (groupname));
		    item->add (YCPTerm (id));
		    item->add (YCPString (groupname));
		    item->add (addBlanks (gid));
		    string all_users = more_users;
		    string userlist = getValue (group, "s_userlist");
		    if (userlist != "") {
			if (all_users != "")
			    all_users += ",";
			all_users += userlist;
		    }
		    // shorten the list if it is too long for table widget
		    // (number of characters are counted, not number of members)
		    if (all_users.size() > ANSWER)
			all_users = all_users.substr (0,
			    all_users.find_first_of (",", ANSWER)) + ",...";
		    item->add (YCPString (all_users));
		    group_items->add (YCPString (groupname), item);
		}
	    }
	    return YCPBoolean(true);
	}
	else {
	   y2error("Wrong path '%s' in Execute().", path->toString().c_str());
	}
    }
    else {
    	y2error("Wrong path '%s' in Execute().", path->toString().c_str());
    }
    return ret;
}

/**
 * otherCommand
 */
YCPValue LdapAgent::otherCommand(const YCPTerm& term)
{
    string sym = term->name();

    if (sym == "LdapAgent") {
        /* Your initialization */
        return YCPVoid();
    }

    return YCPNull();
}
