/* Y2CCLdapAgent.cc
 *
 * Ldap agent implementation
 *
 * Authors: Jiri Suchomel <jsuchome@suse.cz>
 *
 * $Id$
 */

#include <scr/Y2AgentComponent.h>
#include <scr/Y2CCAgentComponent.h>
#include <scr/SCRInterpreter.h>

#include "LdapAgent.h"

typedef Y2AgentComp <LdapAgent> Y2LdapAgentComp;

Y2CCAgentComp <Y2LdapAgentComp> g_y2ccag_ldap ("ag_ldap");
