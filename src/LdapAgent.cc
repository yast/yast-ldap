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
    schema = NULL;
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

/*
 * Search the map for value of given key;
 * key is string and value is integer
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
	// ------------ FIXME: properly check if value is binary ------------
	if (key.find (";binary") != string::npos) {
	    y2warning ("binary value!");
	    BerValue **val = i->getBerValues();
	    // FIXME I take only first value now...
	    BerValue *one_val = val[0];
	    value = YCPByteblock ((const unsigned char*) one_val->bv_val, one_val->bv_len);
	    ber_bvecfree(val);
	}
	// -------------------------------------------------------------------
	else if (single_values && sl.size() == 1)
	    value = YCPString (*(sl.begin()));
	else
	    value = YCPList (list);

	ret->add (YCPString (tolower (key)), YCPValue(value));
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
	entries = ldap->search (dn, 0, "objectclass=*", StringList(), true);
    }
    catch  (LDAPException e) {
        debug_exception (e, "searching for attributes");
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


YCPMap LdapAgent::getGroupEntry (LDAPEntry *entry, string member_attribute)
{
    YCPMap ret;	
    const LDAPAttributeList *al= entry->getAttributes();
    // go through attributes of current entry
    for (LDAPAttributeList::const_iterator i=al->begin(); i!=al->end(); i++) {
	YCPValue value = YCPString ("");
	string key = tolower (i->getName());
	string userlist;
	
	// get the values of current attribute:
	const StringList sl = i->getValues();
	YCPList list = stringlist2ycplist (sl);
	
	if ((sl.size() > 1 || key == member_attribute) && key != "cn")
	{
	    value = YCPList (list);
	}
	else
	{
	    string val = *(sl.begin());
	    if ( key == "gidnumber" )
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


YCPMap LdapAgent::getUserEntry (LDAPEntry *entry)
{
    YCPMap ret;
	
    const LDAPAttributeList *al= entry->getAttributes();
    // go through attributes of current entry
    for (LDAPAttributeList::const_iterator i=al->begin(); i!=al->end(); i++) {
	YCPValue value = YCPString ("");
	string key = tolower (i->getName());
	string userlist;
	
	// get the values of current attribute:
	const StringList sl = i->getValues();
	YCPList list = stringlist2ycplist (sl);
	
	if (sl.size() > 1 && key != "uid")
	{
	    value = YCPList (list);
	}
	else
	{
	    string val = *(sl.begin());
	    if ( key == "gidnumber" || key == "uidnumber")
		value = YCPInteger (atoi (val.c_str()));
	    else
		value = YCPString (val);
	}
	ret->add(YCPString (key), YCPValue(value));
    }
    
    // for the need of yast2-users
    ret->add (YCPString ("type"), YCPString ("ldap"));
    if (ret->value (YCPString("userpassword")).isNull()) {
	ret->add (YCPString ("userpassword"), YCPString ("x"));
    }
    return ret;
}

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

YCPList LdapAgent::stringlist2ycplist (StringList sl)
{
    YCPList l;
    for (StringList::const_iterator n = sl.begin(); n != sl.end();n++){
	l->add (YCPString (*n));
    }
    return l;
}

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
		// list of strings/integers
		new_attr.setValues (ycplist2stringlist (i.value()->asList()));
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
		else
		{
		    attr.setValues (ycplist2stringlist (i.value()->asList()));
		}
	    }
	    else if (i.value()->isByteblock ()) {
		// ------------------------- FIXME -------------------------
		YCPByteblock data = i.value()->asByteblock();

		BerValue *val = (BerValue*) malloc(sizeof(BerValue));

		val->bv_len = data->size();
		val->bv_val = (char*) malloc (sizeof(char)*(data->size()+1));
    
		memcpy (val->bv_val, data->value(), data->size());

		attr.addValue (val);
		ber_bvfree (val);
		// ------------------------- FIXME -------------------------
	    }
	    else continue;
	    modlist->addModification (LDAPModification (attr, op));
	}
    }
}

void LdapAgent::debug_exception (LDAPException e, char* action)
{
    ldap_error = e.getResultMsg();
    ldap_error_code = e.getResultCode();
    y2error ("ldap error while %s (%i): %s", action, ldap_error_code,
	    ldap_error.c_str());
    if (e.getServerMsg() != "")
	y2error ("additional info: %s", e.getServerMsg().c_str());
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

    if (!ldap_initialized) {
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
	    retmap->add (YCPString ("code"), YCPInteger (ldap_error_code));
	    ldap_error = "";
	    ldap_error_code = 0;
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
		filter = "objectclass=*";
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
		    debug_exception (e, "searching");
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
			    y2debug ("dn: %s", entry->getDN().c_str());
			    if (dn_only)
				retlist->add (YCPString (entry->getDN()));
			    else if (return_map) {
				retmap->add (YCPString (entry->getDN()),
				    getSearchedEntry (entry, single_values));
			    }
			    else
				retlist->add (
				    getSearchedEntry (entry, single_values));
			}
			else ok = false;
			delete entry;
		    }
		    catch (LDAPReferralException e) {
			y2error ("caught referral.");
			ldap_error = "referrall"; //TODO what now?
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
		ret->add (YCPString ("must"), stringlist2ycplist_low (oc.getMust()));
		ret->add (YCPString ("may"), stringlist2ycplist_low (oc.getMay()));
		ret->add (YCPString ("sup"), stringlist2ycplist_low (oc.getSup()));
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
	    }
	    else {
		y2error ("No such attributeType: '%s'", name.c_str());
		ldap_error = "at_not_found";
	    }
	    return ret;
	}
	/**
	 * get the mapping of usernames to uid's (used for users module)
	 * Read(.ldap.users.by_name) -> map
	 */
	else if (PC(0) == "users" && PC(1) == "by_name") {
	    return users_by_name;
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
	 * get the map of groups indexed by group names (used for users module)
	 * Read(.ldap.groups.by_name) -> map
	 */
	else if (PC(0) == "groups" && PC(1) == "by_name") {
	    return groups_by_name;
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
		debug_exception (e, "adding");
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
		attrs = getObjectAttributes (dn);
	    }
		
	    // generate the list of modifications from parameters:
	    LDAPModList *modlist = new LDAPModList();
	    generate_mod_list (modlist, argmap2, attrs);

	    // check possible object renaming
	    string rdn = getValue (argmap, "rdn");
	    if (rdn != "") {
		bool delOldRDN 		= getBoolValue (argmap, "delOldRDN");
		string newParentDN	= getValue (argmap, "newParentDN");
		try {
		    ldap->rename (dn, rdn, delOldRDN, newParentDN);
		}
		catch (LDAPException e) {
		    debug_exception (e, "renaming");
		    ret = YCPBoolean (false);
		}
	    }
	    string new_dn = getValue (argmap, "new_dn");
	    if (new_dn != "") {
		dn = new_dn;
	    }
	    y2debug ("(modify call) dn:'%s'", dn.c_str());
	    try {
		ldap->modify (dn, modlist);
	    }
	    catch (LDAPException e) {
		debug_exception (e, "modifying");
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
	    y2debug ("(delete call) dn:'%s'", dn.c_str());
	    try {
		ldap->del (dn);
	    }
	    catch (LDAPException e) {
		debug_exception (e, "deleting");
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
     * initialization: Execute(.ldap, $[ "host": <host>, "port": <port>] )
     */
    if (path->length() == 0) {

	hostname = getValue (argmap, "hostname");
	if (hostname =="") {
	    y2error ("Missing hostname of LDAPHost, aborting");
	    return YCPBoolean (false);
	}

 	port = getIntValue (argmap, "port", DEFAULT_PORT);
 	// int version = getIntValue (argmap, "version", 3); TODO

	// TODO how/where to set this?
	cons = new LDAPConstraints;

	ldap = new LDAPConnection (hostname, port, cons);
	if (!ldap || !cons)
	{
	    y2error ("Error while initializing connection object");
	    ldap_error = "init";
	    return YCPBoolean (false);
	}
	ldap_initialized = true;
	return YCPBoolean(true);
    }
    if (!ldap_initialized) {
	y2error ("Ldap not initialized: use Execute(.ldap) first!");
	ldap_error = "init";
	return YCPBoolean (false);
    }
	
    if (path->length() == 1) {

	/**
	 * bind: Execute(.ldap.bind, $[ "bind_dn": binddn, "bindpw": bindpw] )
	 * for anonymous acess, call bind with empty map
	 */
	if (PC(0) == "bind") {

	    bind_dn = getValue (argmap, "bind_dn");
	    bind_pw = getValue (argmap, "bind_pw");
			
	    try {
		ldap->bind (bind_dn, bind_pw, cons);
	    }
	    catch (LDAPException e) {
		debug_exception (e, "binding");
		return YCPBoolean (false);
	    }
	    return YCPBoolean(true);
	}
	else if (PC(0) == "unbind") {
	    ldap->unbind();
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
		entries = ldap->search (schema_dn, 0, "objectclass=*", sl);
	    }
	    catch  (LDAPException e) {
		debug_exception (e, "searching");
		return YCPBoolean (true);
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
		member_attribute	= "uniquemember";

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
//	    map <int, string> s_more_usersmap; - generate from map?

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
		    y2warning ("object not found");
		}
		else {
		    debug_exception (e, "searching");
		    return YCPBoolean (false);
		}
            }

	    // initialize the maps/lists to be filled
	    users = YCPMap();
	    users_by_name = YCPMap();
	    groups = YCPMap();
	    groups_by_name = YCPMap();

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
		    int gid = getIntValue (group, "gidnumber", -1);
		    if (gid == -1) {
			y2warning("Group '%s' has no gidnumber?",
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
		    // FIXME: should "uniquemember" be replaced with a map,
		    // or it is better to use some generic name ('userlist')?
		    group->add (YCPString (member_attribute), usermap);
//		    group->add (YCPString ("userlist"), usermap);
		    // change list of users to string (need only for itemlist)
		    if (itemlists) {
			group->add (YCPString ("s_userlist"), YCPString(s_ul));
		    }
		    group->add (YCPString ("more_users"), YCPMap ());
		    // ------- finally add new item to return maps
		    groups->add (YCPInteger (gid), group);
		    groupnames->add (YCPString (groupname), YCPInteger(1));
		    gids->add (YCPInteger (gid), YCPInteger(1));
		}
		else ok = false;
		delete entry;
	      }
	      catch (LDAPReferralException e) {
		y2error ("caught referral.");
		ldap_error = "referrall"; 
	      }
	      catch  (LDAPException e) {
		debug_exception (e, "going through search result");
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
		debug_exception (e, "searching");
		return YCPBoolean (false);
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
		    int uid = getIntValue (user, "uidnumber", -1);
		    if (uid == -1) {
			y2warning("User with dn '%s' has no uidnumber?",
			    dn.c_str());
			continue;
		    }
		    // get the name of default group
		    int gid = getIntValue (user, "gidnumber", -1);
		    string groupname;
		    if (!groups->value(YCPInteger(gid)).isNull())
			groupname = getValue (
			  groups->value (YCPInteger(gid))->asMap(),"cn");
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
		    /*
		    if (more_usersmap.find (gid) != more_usersmap.end())
			more_usersmap [gid] += ",";
		    more_usersmap [gid] += username;
		    */
		    (more_usersmap [gid])->add (YCPString (username), YCPInteger(1));
		    // generate itemlist
		    if (itemlists) {
			YCPTerm item ("item"), id ("id");
			id->add (YCPInteger (uid));
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
			user_items->add (YCPInteger (uid), item);
		    }
		    
		    // ------- finally add new item to return maps
		    users->add (YCPInteger (uid), user);
		    // helper structures for faster searching in users module
		    users_by_name->add (YCPString (username), YCPInteger (uid));
		    uids->add (YCPInteger (uid), YCPInteger(1));
		    usernames->add (YCPString (username), YCPInteger(1));
		    userdns->add (YCPString (dn), YCPInteger(1));
		    string home = getValue (user,"homedirectory");
		    if (home != "") {
			homes->add (YCPString (home), YCPInteger(1));
		    }
		}
		else ok = false;
		delete entry;
	      }
	      catch (LDAPReferralException e) {
		y2error ("caught referral.");
		ldap_error = "referrall";
	      }
	      catch  (LDAPException e) {
		debug_exception (e, "going through search result");
	      }
	    }
            }

	    // once again, go through groups and update group maps	    
	    for (YCPMapIterator i = groups->begin(); i != groups->end(); i++) {

		YCPMap group = i.value()->asMap();
		int gid = i.key()->asInteger()->value();
		string groupname = getValue (group, "cn");
		string more_users; // TODO for itemlist!
		if (more_usersmap.find (gid) != more_usersmap.end()) {
		    group->add (YCPString ("more_users"), more_usersmap[gid]);
		    // FIXME better to add directly while processing users...
		    groups->add (YCPInteger (gid), group);
		}
		// generate itemlist if wanted
		if (itemlists) {
		    YCPTerm item ("item"), id ("id");
		    id->add (YCPInteger (gid));
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
		    group_items->add (YCPInteger (gid), item);
		}
		groups_by_name->add (YCPString (groupname), YCPInteger (gid));
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
