/* LdapAgent.cc
 *
 * An agent for reading the ldap configuration file.
 *
 * Authors: Jiri Suchomel <jsuchome@suse.cz>
 *
 * $Id$
 */

#include "LdapAgent.h"

#define PC(n)       (path->component_str(n))

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
    ldap = new LDAPConnection ();
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
}

/*
 * search the map for value of given key; both key and value have to be strings
 */
string LdapAgent::getValue (const YCPMap map, const string key)
{
    if (map->haskey(YCPString(key)) && map->value(YCPString(key))->isString())
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
    if (map->haskey(YCPString(key)) && map->value(YCPString(key))->isInteger())
	return map->value(YCPString(key))->asInteger()->value(); 
    else
	return deflt;
}

/*
 * Search the map for value of given key;
 * key is string and value is boolean
 */
bool LdapAgent::getBoolValue (const YCPMap map, const string key)
{
    if (map->haskey(YCPString(key)) && map->value(YCPString(key))->isBoolean())
	return map->value(YCPString(key))->asBoolean()->value(); 
    else
	return false;
}

/*
 * Search the map for value of given key;
 * key is string and value is YCPList
 */
YCPList LdapAgent::getListValue (const YCPMap map, const string key)
{
    if (map->haskey(YCPString(key)) && map->value(YCPString(key))->isList())
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
	YCPList list;
	// get the values of current attribute:
	const StringList sl = i->getValues();

	for (StringList::const_iterator n = sl.begin(); n != sl.end(); n++) {
	    list->add(YCPString(*n));
	}
	if (single_values && sl.size() == 1)
	    value = YCPString (*(sl.begin()));
	else
	    value = YCPList (list);

//y2internal ("key: %s, value: %s", i->getName().c_str(), (*(sl.begin())).c_str()); 
	ret->add(YCPString(i->getName()), YCPValue(value));
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
	entries = ldap->search (dn, 0, "objectClass=*", StringList(), true);
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
    delete entries;
    return ret;
}


YCPMap LdapAgent::getGroupEntry (LDAPEntry *entry)
{
    YCPMap ret;	
    const LDAPAttributeList *al= entry->getAttributes();
    // go through attributes of current entry
    for (LDAPAttributeList::const_iterator i=al->begin(); i!=al->end(); i++) {
	YCPValue value = YCPString ("");
	YCPList list;
	string key = i->getName();
	string userlist;
	
	// get the values of current attribute:
	const StringList sl = i->getValues();
	
	// translate some keys for users-module usability
	// all other attributes have the same name as in LDAP schema
	if (key == "gidNumber")
	    key = "gid";
	else if (key == "cn")
	    key = "groupname";
	else if (key == "memberUid")
	{
	    key = "userlist";
	}

	for (StringList::const_iterator n = sl.begin(); n != sl.end(); n++) {
	    list->add (YCPString (*n));
	}
	if (sl.size() > 1 || key == "userlist")
	{
	    value = YCPList (list);
	}
	else
	{
	    string val = *(sl.begin());
	    // TODO check other types?
	    if ( key == "gid" )
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
	YCPList list;
	string key = i->getName();
	string userlist;
	
	// get the values of current attribute:
	const StringList sl = i->getValues();
	
	// translate some keys for users-module usability
	// all other attributes have the same name as in LDAP schema
	if (key == "uidNumber")
	    key = "uid";
	else if (key == "gidNumber")
	    key = "gid";
	else if (key == "cn")
	    key = "fullname";
	else if (key == "uid") // from object config: searchUri?
	    key = "username";
	else if (key == "homeDirectory")
	    key = "home";
	else if (key == "loginShell")
	    key = "shell";

	// TODO what about shadow entries?
	if (sl.size() > 1)
	{
	    for (StringList::const_iterator n = sl.begin(); n != sl.end();n++){
		list->add (YCPString (*n));
	    }
	    value = YCPList (list);
	}
	else
	{
	    string val = *(sl.begin());
	    // TODO check other types
	    if ( key == "gid" || key == "uid")
		value = YCPInteger (atoi (val.c_str()));
	    else
		value = YCPString (val);
	}
	ret->add(YCPString (key), YCPValue(value));
    }
    
    // for the need of yast2-users
    ret->add (YCPString ("type"), YCPString ("ldap"));
    ret->add (YCPString ("password"), YCPString ("x"));
    return ret;
}

StringList LdapAgent::ycplist2stringlist (YCPList l)
{
    StringList sl;
    for (int i=0; i < l->size(); i++) {
	sl.add (l->value(i)->asString()->value());
    }
    return sl;
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
	    else if (i.value()->isList()) {
		if (i.value()->asList()->isEmpty())
		    continue;
		new_attr.setValues (ycplist2stringlist (i.value()->asList()));
	    }
	    else continue;
	    attrs->addAttribute (new_attr);
	}
    }
}
		
/**
 * creates list of modifications for LDAP object
 * for removing attribute, use give it empty value
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
		present = attrs->asMap()->haskey(YCPString (key));
	    }
	    if (i.value()->isString()) {
		string val = i.value()->asString()->value();
		if (val == "") {
		    if (!present) {
			y2warning ("No such attribute '%s'", key.c_str());
			continue;
		    }
		    op = LDAPModification::OP_DELETE;
		}
		else
		    attr.addValue (i.value()->asString()->value());
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
		    attr.setValues (ycplist2stringlist (i.value()->asList()));
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
YCPValue LdapAgent::Dir(const YCPPath& path)
{
    y2error("Wrong path '%s' in Read().", path->toString().c_str());
    return YCPVoid();
}

/**
 * Read
 */
YCPValue LdapAgent::Read(const YCPPath &path, const YCPValue& arg)
{
    y2milestone("path in Read: '%s'.", path->toString().c_str());
    YCPValue ret = YCPVoid();
	
    YCPMap argmap;
    if (!arg.isNull() && arg->isMap())
    	argmap = arg->asMap();

    if (!ldap_initialized) {
	y2error ("Ldap not initialized: use Execute(.ldap) first!");
	ldap_error = "initialize";
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
 
	    StringList attrs = ycplist2stringlist(getListValue(argmap,"attrs"));
			
	    // do the search call
	    LDAPSearchResults* entries = NULL;
	    try {
		entries = ldap->search (
		    base_dn, scope, filter, attrs, attrsOnly, cons);
	    }
	    catch  (LDAPException e) {
		debug_exception (e, "searching");
		return ret;
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
//			    y2internal ("dn: %s", entry->getDN().c_str());
			    if (return_map) {
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
	 * get the mapping of usernames to uid's (used for users module)
	 * Read(.ldap.users.by_name) -> map
	 */
	if (PC(0) == "users" && PC(1) == "by_name") {
	    return users_by_name;
	}
	/**
	 * get the list of home directories (used for users module)
	 * Read(.ldap.users.homes) -> list of homes
	 */
	if (PC(0) == "users" && PC(1) == "homes") {
	    return homelist;
	}
	/**
	 * get the list of UID's (used for users module)
	 * Read(.ldap.users.uids) -> list
	 */
	if (PC(0) == "users" && PC(1) == "uids") {
	    return uidlist;
	}
	/**
	 * get the list of user names (used for users module)
	 * Read(.ldap.users.usernames) -> list
	 */
	if (PC(0) == "users" && PC(1) == "usernames") {
	    return usernamelist;
	}
	/**
	 * get the items for user table (used for users module)
	 * Read(.ldap.users.itemlist) -> list of items
	 */
	if (PC(0) == "users" && PC(1) == "itemlist") {
	    return users_itemlist;
	}
	/**
	 * get the map of groups indexed by group names (used for users module)
	 * Read(.ldap.groups.by_name) -> map
	 */
	if (PC(0) == "groups" && PC(1) == "by_name") {
	    return groups_by_name;
	}
	/**
	 * get the list of GID's (used for users module)
	 * Read(.ldap.groups.gids) -> list
	 */
	if (PC(0) == "groups" && PC(1) == "gids") {
	    return gidlist;
	}
	/**
	 * get the list of group names (used for users module)
	 * Read(.ldap.groups.groupnames) -> list
	 */
	if (PC(0) == "groups" && PC(1) == "groupnames") {
	    return groupnamelist;
	}
	/**
	 * get the items for group table (used for users module)
	 * Read(.ldap.groups.itemlist) -> list of items
	 */
	if (PC(0) == "groups" && PC(1) == "itemlist") {
	    return groups_itemlist;
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
YCPValue LdapAgent::Write(const YCPPath &path, const YCPValue& arg,
       const YCPValue& arg2)
{
    y2milestone("path in Write: '%s'.", path->toString().c_str());

    YCPValue ret = YCPBoolean(true);
    
    YCPMap argmap, argmap2;
    if (!arg.isNull() && arg->isMap())
	argmap = arg->asMap();
    if (!arg2.isNull() && arg2->isMap())
	argmap2 = arg2->asMap();

    if (!ldap_initialized) {
	y2error ("Ldap not initialized: use Execute(.ldap) first!");
	ldap_error = "initialize";
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

	    try {
		ldap->modify (dn, modlist);
	    }
	    catch (LDAPException e) {
		debug_exception (e, "modifying");
		delete modlist;
		return YCPBoolean (false);
	    }
	    // now check possible object renaming
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
    y2milestone("path in Execute: '%s'.", path->toString().c_str());
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
	    ldap_error = "initialize";
	    return YCPBoolean (false);
	}
	ldap_initialized = true;
	return YCPBoolean(true);
    }
    if (!ldap_initialized) {
	y2error ("Ldap not initialized: use Execute(.ldap) first!");
	ldap_error = "initialize";
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
	    int user_scope	= getIntValue (argmap, "user_scope", 2);
	    int group_scope	= getIntValue (argmap, "group_scope", 2);
	    bool itemlists	= getBoolValue (argmap, "itemlists");
	    StringList user_attrs = ycplist2stringlist (
		    getListValue(argmap, "user_attrs"));
   	    StringList group_attrs = ycplist2stringlist (
		    getListValue(argmap, "group_attrs"));

	    // for each user, store groups that user belongs to:
	    map <string, string > grouplists;
	    // for each group, store users having this group as default:
	    map <int, string> more_usersmap;
   
	    // first, search for groups
	    LDAPSearchResults* entries = NULL;
	    try {
		entries = ldap->search (group_base, group_scope, group_filter,
		       group_attrs, false, cons);
	    }
	    catch  (LDAPException e) {
		debug_exception (e, "searching");
		return YCPBoolean (false);
            }
	    // now generate group map (to use with users)
	    if (entries != 0) {
	    
	    LDAPEntry* entry = new LDAPEntry();
	    bool ok = true;
	    while (ok) {
	      try {
		entry = entries->getNext();
		if (entry != 0) {
		    YCPMap group = getGroupEntry (entry);
		    group->add (YCPString("dn"), YCPString(entry->getDN()));
		    int gid = getIntValue (group, "gid", -1);
		    if (gid == -1) {
			y2warning("Group '%s' has no gidNumber?",
			    entry->getDN().c_str());
			continue;
		    }
		    string groupname = getValue (group, "groupname");
		    
		    // go through userlist of this group
		    YCPList ul = getListValue (group, "userlist");
		    string s_ul;
		    for (int i=0; i < ul->size(); i++) {
			// for each user in userlist add this group to the
			// map of type "user->his groups"
			string user = ul->value(i)->asString()->value();
			if (grouplists.find (user) != grouplists.end())
			    grouplists [user] += ",";
			grouplists[user] += groupname;
			if (i>0) s_ul += ",";
			s_ul += user;
		    }
		    // change list of users to string
		    group->add (YCPString ("userlist"), YCPString(s_ul));
		    // ------- finally add new item to return maps
		    groups->add (YCPInteger (gid), group);
		    groupnamelist->add (YCPString (groupname));
		    gidlist->add (YCPInteger (gid));
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
		    user->add (YCPString("dn"), YCPString(entry->getDN()));
		    // check it
		    int uid = getIntValue (user, "uid", -1);
		    if (uid == -1) {
			y2warning("User with dn '%s' has no uidNumber?",
			    entry->getDN().c_str());
			continue;
		    }
		    // get the name of default group
		    int gid = getIntValue (user, "gid", -1);
		    string groupname;
		    if (groups->haskey(YCPInteger(gid)))
			groupname = getValue (
			  groups->value (YCPInteger(gid))->asMap(),"groupname");
		    if (groupname != "")
			user->add (YCPString("groupname"),YCPString(groupname));

		    // get the list of groups user belongs to
		    string username = getValue (user, "username");
		    string grouplist; 
		    if (grouplists.find (username) != grouplists.end())
			grouplist = grouplists[username];
		    user->add (YCPString ("grouplist"), YCPString (grouplist));
		    // default group of this user has to know of this user:
		    if (more_usersmap.find (gid) != more_usersmap.end())
			more_usersmap [gid] += ",";
		    more_usersmap [gid] += username;
		    // generate itemlist
		    if (itemlists) {
			YCPTerm item ("item", true), id ("id", true);
			id->add (YCPInteger (uid));
			item->add (YCPTerm (id));
			item->add (YCPString (username));
			item->add (YCPString (getValue (user, "fullname")));
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
			users_itemlist->add (item);
		    }
		    
		    // ------- finally add new item to return maps
		    users->add (YCPInteger (uid), user);
		    // helper structures for faster searching in users module
		    users_by_name->add (YCPString (username), YCPInteger (uid));
		    uidlist->add (YCPInteger (uid));
		    usernamelist->add (YCPString (username));
		    homelist->add (YCPString (getValue (user, "home")));

		    // TODO last uid -> use Ralf's proposal
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

	    // once again, go through groups and update group maps	    
	    for (YCPMapIterator i = groups->begin(); i != groups->end(); i++) {

		YCPMap group = i.value()->asMap();
		int gid = i.key()->asInteger()->value();
		string groupname = getValue (group, "groupname");
		string more_users;
		if (more_usersmap.find (gid) != more_usersmap.end()) {
		    more_users = more_usersmap [gid];
		    group->add (YCPString ("more_users"),YCPString(more_users));
		}
		// generate itemlist if wanted
		if (itemlists) {
		    YCPTerm item ("item", true), id ("id", true);
		    id->add (YCPInteger (gid));
		    item->add (YCPTerm (id));
		    item->add (YCPString (groupname));
		    item->add (addBlanks (gid));
		    string all_users = more_users;
		    string userlist = getValue (group, "userlist");
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
		    groups_itemlist->add (item);
		}
		groups_by_name->add (YCPString (groupname), group);
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
    string sym = term->symbol()->symbol();

    if (sym == "LdapAgent") {
        /* Your initialization */
        return YCPVoid();
    }

    return YCPNull();
}
