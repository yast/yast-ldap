/* LdapAgent.h
 *
 * Ldap agent implementation
 *
 * Authors: Jiri Suchomel <jsuchome@suse.cz>
 *
 * $Id$
 */

#ifndef _LdapAgent_h
#define _LdapAgent_h

#include <Y2.h>
#include <scr/SCRAgent.h>

#include <LDAPConnection.h>
#include <LDAPException.h>
#include <LDAPReferralException.h>
#include <LDAPAttributeList.h>
#include <LDAPAttribute.h>

#include <LDAPSchema.h>

#define DEFAULT_PORT 389
#define ANSWER	42
#define MAX_LENGTH_ID 5

/**
 * @short An interface class between YaST2 and Ldap Agent
 */
class LdapAgent : public SCRAgent
{
private:
    /**
     * Agent private variables
     */
    int port;
    string hostname;
    string bind_dn;
    string bind_pw;
    string ldap_error;
    string server_error;

    int ldap_error_code;
    bool ldap_initialized;

    string userpw_hash;

    LDAPConnection *ldap;
    LDAPConstraints *cons;
    LDAPSchema *schema;

    YCPMap  users,
	    users_by_name,
	    usernames,
	    userdns,
	    uids,
	    homes,
	    user_items,
	    groups,
	    groups_by_name,
	    groupnames,
	    gids,
	    group_items;

    string getValue ( const YCPMap map, const string key);

    /**
     * Search the map for value of given key;
     * key is string and value is integer
     */
    int getIntValue ( const YCPMap map, const string key, int deflt);
    bool getBoolValue (const YCPMap map, const string key);
    YCPList getListValue (const YCPMap map, const string key);

    /**
     * converts YCPList to StringList object
     */
    StringList ycplist2stringlist (YCPList l);
    
    /**
     * converts StringList object to YCPList value
     */
    YCPList stringlist2ycplist (StringList sl);
    YCPList LdapAgent::stringlist2ycplist_low (StringList sl);

    YCPMap getGroupEntry (LDAPEntry *entry, string member_attribute);
    YCPMap getUserEntry (LDAPEntry *entry);

    /**
     * creates YCPMap describing object returned as a part of LDAP search call
     * @param single_values if true, return string when argument has only
     * one value (otherwise return always list)
     */
    YCPMap getSearchedEntry (LDAPEntry *entry, bool sinlge_value);

    /**
     * searches for one object and gets all his non-empty attributes
     * @param dn object's dn
     * @return map of type $[ attr_name: [] ]
     */
    YCPMap getObjectAttributes (string dn);

    /**
     * deletes all children of given entry
     */
    YCPBoolean deleteSubTree (string dn);

    /**
     * move the entry in LDAP tree with all its children
     */
    YCPBoolean moveWithSubtree (string dn, string new_dn, string parent_dn);
    
    /**
     * copy the LDAP entry to new place
     * (+ changes DN-constructing attribute, like cn,uid,ou etc.)
     */
    YCPBoolean copyOneEntry (string dn, string new_dn);
 
    void debug_exception (LDAPException e, string action);

    /**
     * creates attributes for new LDAP object and fills their values 
     */
    void generate_attr_list (LDAPAttributeList* attrs, YCPMap map);

    /**
     * creates list of modifications for LDAP object
     * for removing attribute, use give it empty value
     */
    void generate_mod_list (LDAPModList* modlist, YCPMap map, YCPValue attrs);

public:
    /**
     * Default constructor.
     */
    LdapAgent();

    /**
     * Destructor.
     */
    virtual ~LdapAgent();

    /**
     * Provides SCR Read ().
     * @param path Path that should be read.
     * @param arg Additional parameter.
     */
    virtual YCPValue Read ( const YCPPath &path,
			    const YCPValue& arg = YCPNull(),
			    const YCPValue& opt = YCPNull());

    /**
     * Provides SCR Write ().
     */
    virtual YCPBoolean Write(const YCPPath &path,
			   const YCPValue& arg,
			   const YCPValue& arg2 = YCPNull());

    /**
     * Provides SCR Execute ().
     */
    virtual YCPValue Execute(const YCPPath &path,
			     const YCPValue& arg = YCPNull(),
			     const YCPValue& arg2 = YCPNull());

    /**
     * Provides SCR Dir ().
     */
    virtual YCPList Dir(const YCPPath& path);

    /**
     * Used for mounting the agent.
     */
    virtual YCPValue otherCommand(const YCPTerm& term);
};

#endif /* _LdapAgent_h */
