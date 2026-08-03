"""Entra ID Blast Radius.

Given a single identity, compute the complete set of everything it can
reach - directly and transitively - and rank that reachable set by the
worst privilege at the end.

This is the inverse of an attack-path scan. An attack-path scan asks
"who can reach the crown jewels?" and walks toward privilege. Blast
radius asks "if THIS identity is compromised, what is the full extent
of what the attacker now controls?" and walks outward from the identity.

v1 edge types:
  - direct role assignments held by the principal
  - group memberships (transitive / nested, via Graph transitiveMemberOf)
  - roles granted through any of those groups
  - PIM-eligible roles (direct or via a group) - dormant privilege
  - applications the principal owns (and what those apps can do)

Output is console-first: a ranked reachable set with the single worst
thing called out as the headline.
"""

import asyncio
import base64
import json as _json

import aiohttp
from azure.identity import InteractiveBrowserCredential
from msgraph import GraphServiceClient
from colorama import Fore, Style, init

init(autoreset=True)


# --- Role tiering: what "worst" means, reused from the attack-path model ---

TIER_0_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
}
TIER_1_ROLES = {
    "Application Administrator",
    "Cloud Application Administrator",
    "Security Administrator",
    "Conditional Access Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Administrator",
}

# lower number = worse
TIER_RANK = {"TIER0": 0, "TIER1": 1, "TIER2": 2}

# App (Graph) permissions that make OWNING an app dangerous. Owning an app
# means controlling what it can do - so an owned app holding one of these is
# effectively that level of access for the owner, regardless of their roles.
APP_TIER0 = {
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Directory.ReadWrite.All",
    "PrivilegedAccess.ReadWrite.AzureADGroup",
}
APP_TIER1 = {
    "Mail.Read", "Mail.ReadWrite", "Mail.Send",
    "Files.Read.All", "Files.ReadWrite.All",
    "Sites.Read.All", "Sites.ReadWrite.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "Chat.Read.All", "ChannelMessage.Read.All",
}


def _tier(role_name):
    if role_name in TIER_0_ROLES:
        return "TIER0"
    if role_name in TIER_1_ROLES:
        return "TIER1"
    return "TIER2"


class BlastRadius:
    """Computes what a single principal can reach."""

    SCOPES = [
        "User.Read.All",
        "Group.Read.All",
        "Directory.Read.All",
        "RoleManagement.Read.All",
        "RoleManagement.Read.Directory",
        "RoleEligibilitySchedule.Read.Directory",
        "Application.Read.All",
    ]
    CLIENT_ID = "7be5ba65-ddcd-4ae9-bf94-747a6e38e9ad"

    def __init__(self):
        self.credential = None
        self.client = None
        self.access_token = None

    async def connect(self):
        print(f"{Fore.YELLOW}Connecting to Microsoft Graph...{Style.RESET_ALL}")
        self.credential = InteractiveBrowserCredential(client_id=self.CLIENT_ID)
        self.client = GraphServiceClient(credentials=self.credential, scopes=self.SCOPES)
        token = self.credential.get_token("https://graph.microsoft.com/.default")
        self.access_token = token.token
        print(f"{Fore.GREEN}Connected.{Style.RESET_ALL}")

    # --- resolve the starting principal (UPN or object id) ---

    async def resolve_principal(self, identifier):
        """Accept a UPN (jane@tenant.com) or an object id, return the user."""
        # object ids are GUIDs; UPNs contain '@'. Try direct get either way.
        try:
            user = await self.client.users.by_user_id(identifier).get()
            if user:
                return user
        except Exception:
            pass
        # fallback: filter by userPrincipalName
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            url = (
                "https://graph.microsoft.com/v1.0/users"
                f"?$filter=userPrincipalName eq '{identifier}'&$select=id,displayName,userPrincipalName"
            )
            async with aiohttp.ClientSession() as s:
                async with s.get(url, headers=headers) as r:
                    if r.status == 200:
                        data = await r.json()
                        vals = data.get("value", [])
                        if vals:
                            return vals[0]
        except Exception as e:
            print(f"{Fore.RED}Could not resolve '{identifier}': {e}{Style.RESET_ALL}")
        return None

    def _pid(self, principal):
        """Object id from either an SDK user object or a raw dict."""
        return getattr(principal, "id", None) or principal.get("id")

    def _pname(self, principal):
        return (
            getattr(principal, "display_name", None)
            or (principal.get("displayName") if isinstance(principal, dict) else None)
            or "Unknown"
        )

    # --- edge collectors (all keyed to the principal's object id) ---

    async def _get_json(self, url):
        headers = {"Authorization": f"Bearer {self.access_token}"}
        rows = []
        async with aiohttp.ClientSession() as s:
            while url:
                async with s.get(url, headers=headers) as r:
                    if r.status != 200:
                        break
                    data = await r.json()
                    rows.extend(data.get("value", []))
                    url = data.get("@odata.nextLink")
        return rows

    async def transitive_groups(self, principal_id):
        """All groups the principal belongs to, nesting included.

        Graph's transitiveMemberOf computes nested membership server-side,
        so we don't hand-walk group nesting.
        """
        url = (
            f"https://graph.microsoft.com/v1.0/users/{principal_id}"
            "/transitiveMemberOf/microsoft.graph.group?$select=id,displayName"
        )
        return await self._get_json(url)

    async def direct_role_assignments(self, principal_id):
        """Roles assigned directly to the principal (not via a group)."""
        url = (
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
            f"?$filter=principalId eq '{principal_id}'&$expand=roleDefinition"
        )
        rows = await self._get_json(url)
        out = []
        for a in rows:
            rd = a.get("roleDefinition") or {}
            name = rd.get("displayName", "Unknown role")
            out.append({"role": name, "via": "direct", "kind": "active"})
        return out

    async def group_role_assignments(self, group_ids):
        """Roles held by any of the principal's groups -> reachable by the
        principal through that group membership."""
        out = []
        for gid, gname in group_ids:
            url = (
                "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
                f"?$filter=principalId eq '{gid}'&$expand=roleDefinition"
            )
            rows = await self._get_json(url)
            for a in rows:
                rd = a.get("roleDefinition") or {}
                out.append({
                    "role": rd.get("displayName", "Unknown role"),
                    "via": f"group:{gname}",
                    "kind": "active",
                })
        return out

    async def pim_eligible(self, principal_id, group_ids):
        """PIM-eligible roles for the principal directly, or via a group."""
        ids = {principal_id: "direct"}
        for gid, gname in group_ids:
            ids[gid] = f"group:{gname}"
        out = []
        rows = await self._get_json(
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules"
            "?$expand=roleDefinition"
        )
        for a in rows:
            pid = a.get("principalId")
            if pid in ids:
                rd = a.get("roleDefinition") or {}
                out.append({
                    "role": rd.get("displayName", "Unknown role"),
                    "via": ids[pid],
                    "kind": "eligible",
                })
        return out

    async def owned_apps(self, principal_id):
        """Applications the principal owns, with the granted app permissions
        that make ownership dangerous.

        Owning an app means controlling its permissions. An owned app holding
        a tier-0 Graph permission (e.g. RoleManagement.ReadWrite.Directory) is
        effectively tenant takeover for the owner, even if the owner holds no
        such role directly. That is the cross-dimension reach blast radius must
        surface.
        """
        apps = await self._get_json(
            f"https://graph.microsoft.com/v1.0/users/{principal_id}"
            "/ownedObjects/microsoft.graph.application?$select=id,displayName,appId"
        )
        out = []
        for a in apps:
            app_id = a.get("appId")
            perms = await self._app_permissions(app_id)
            tier0 = sorted(perms & APP_TIER0)
            tier1 = sorted(perms & APP_TIER1)
            worst = "TIER0" if tier0 else ("TIER1" if tier1 else "TIER2")
            out.append({
                "app": a.get("displayName", "Unknown app"),
                "app_id": app_id,
                "tier0_perms": tier0,
                "tier1_perms": tier1,
                "worst": worst,
            })
        return out

    async def _app_permissions(self, app_id):
        """Resolve the Graph application permissions actually granted to an
        app's service principal, returning the permission value strings.

        The SP's appRoleAssignments reference (resourceId, appRoleId); the
        permission name lives in the RESOURCE SP's appRoles list. We resolve
        the pair to the human permission value (e.g. "Mail.Read").
        """
        if not app_id:
            return set()
        # find the app's own service principal by appId
        sps = await self._get_json(
            "https://graph.microsoft.com/v1.0/servicePrincipals"
            f"?$filter=appId eq '{app_id}'&$select=id,appId,displayName"
        )
        if not sps:
            return set()
        sp_oid = sps[0]["id"]
        assignments = await self._get_json(
            f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_oid}/appRoleAssignments"
        )
        perms = set()
        # cache resource SP appRoles so we resolve appRoleId -> value
        role_cache = {}
        for a in assignments:
            resource_id = a.get("resourceId")
            role_id = a.get("appRoleId")
            if not resource_id or not role_id:
                continue
            if resource_id not in role_cache:
                res = await self._get_json(
                    f"https://graph.microsoft.com/v1.0/servicePrincipals/{resource_id}?$select=appRoles"
                )
                # _get_json returns a list of 'value' rows; a single object
                # response has no 'value', so fetch directly instead
                role_cache[resource_id] = await self._sp_app_roles(resource_id)
            roles = role_cache[resource_id]
            perms.add(roles.get(role_id, role_id))
        return perms

    async def _sp_app_roles(self, sp_oid):
        """Map appRoleId -> permission value for a service principal."""
        headers = {"Authorization": f"Bearer {self.access_token}"}
        url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_oid}?$select=appRoles"
        async with aiohttp.ClientSession() as s:
            async with s.get(url, headers=headers) as r:
                if r.status != 200:
                    return {}
                data = await r.json()
        return {role["id"]: role.get("value", role["id"]) for role in data.get("appRoles", [])}

    # --- top-level compute ---

    async def compute(self, identifier):
        principal = await self.resolve_principal(identifier)
        if not principal:
            print(f"{Fore.RED}No principal found for '{identifier}'.{Style.RESET_ALL}")
            return None

        pid = self._pid(principal)
        pname = self._pname(principal)
        print(f"\n{Fore.CYAN}Computing blast radius for {pname} ({pid})...{Style.RESET_ALL}")

        groups = await self.transitive_groups(pid)
        group_ids = [(g["id"], g.get("displayName", "Unknown group")) for g in groups]

        direct_roles = await self.direct_role_assignments(pid)
        group_roles = await self.group_role_assignments(group_ids)
        eligible = await self.pim_eligible(pid, group_ids)
        apps = await self.owned_apps(pid)

        roles = direct_roles + group_roles + eligible
        # de-duplicate role reachability by (role, via, kind)
        seen = set()
        unique_roles = []
        for r in roles:
            key = (r["role"], r["via"], r["kind"])
            if key not in seen:
                seen.add(key)
                unique_roles.append(r)

        for r in unique_roles:
            r["tier"] = _tier(r["role"])

        unique_roles.sort(key=lambda r: (TIER_RANK.get(r["tier"], 9), r["kind"] != "active"))

        # Overall worst reachable considers roles AND owned-app permissions.
        worst_role_tier = min((TIER_RANK[r["tier"]] for r in unique_roles), default=9)
        worst_app_tier = min((TIER_RANK[a["worst"]] for a in apps), default=9)
        overall = min(worst_role_tier, worst_app_tier)

        return {
            "principal": {"id": pid, "name": pname},
            "groups": group_ids,
            "roles": unique_roles,
            "apps": apps,
            "overall_tier": overall,
            "worst_via_app": worst_app_tier < worst_role_tier,
        }


def _print_report(result):
    if not result:
        return
    p = result["principal"]
    roles = result["roles"]
    groups = result["groups"]
    apps = result["apps"]

    print("\n" + "=" * 64)
    print(f"BLAST RADIUS: {p['name']}")
    print("=" * 64)

    overall = result.get("overall_tier", 9)
    via_app = result.get("worst_via_app", False)
    tier0_apps = [a for a in apps if a["worst"] == "TIER0"]

    # headline: worst reachable across roles AND owned apps
    if overall == 0:
        if via_app and tier0_apps:
            a = tier0_apps[0]
            perm = a["tier0_perms"][0] if a["tier0_perms"] else "tier-0 permission"
            print(f"{Fore.RED}!! Reaches FULL TENANT CONTROL via OWNED APP "
                  f"'{a['app']}' ({perm}){Style.RESET_ALL}")
            print(f"{Fore.RED}   (owner holds no tier-0 role directly - the reach is through the app){Style.RESET_ALL}")
        else:
            worst = roles[0]
            print(f"{Fore.RED}!! Reaches FULL TENANT CONTROL: {worst['role']} "
                  f"({'held' if worst['kind']=='active' else 'PIM-eligible'} via {worst['via']}){Style.RESET_ALL}")
    elif roles:
        worst = roles[0]
        print(f"{Fore.YELLOW}Worst reachable: {worst['role']} via {worst['via']}{Style.RESET_ALL}")
    elif tier0_apps:
        a = tier0_apps[0]
        print(f"{Fore.RED}!! Reaches FULL TENANT CONTROL via OWNED APP '{a['app']}'{Style.RESET_ALL}")
    else:
        print("No privileged roles or dangerous owned apps reachable.")

    print(f"\nReach: {len(groups)} groups, {len(roles)} role assignments, {len(apps)} owned apps\n")

    if roles:
        print("Reachable roles (worst first):")
        for r in roles:
            tag = {"TIER0": "[T0]", "TIER1": "[T1]", "TIER2": "[T2]"}[r["tier"]]
            kind = "held" if r["kind"] == "active" else "PIM-eligible"
            print(f"  {tag} {r['role']:40} {kind:14} via {r['via']}")

    if apps:
        print("\nOwned applications (own the app = control its permissions):")
        for a in sorted(apps, key=lambda x: TIER_RANK.get(x["worst"], 9)):
            if a["tier0_perms"]:
                print(f"  {Fore.RED}[T0]{Style.RESET_ALL} {a['app']:32} "
                      f"holds {', '.join(a['tier0_perms'])}")
            elif a["tier1_perms"]:
                print(f"  {Fore.YELLOW}[T1]{Style.RESET_ALL} {a['app']:32} "
                      f"holds {', '.join(a['tier1_perms'])}")
            else:
                print(f"       {a['app']}")

    if groups:
        print(f"\nGroup memberships ({len(groups)}, nesting included):")
        for gid, gname in groups[:20]:
            print(f"  - {gname}")
        if len(groups) > 20:
            print(f"  ... and {len(groups) - 20} more")
    print()


async def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python blast_radius.py <UPN-or-object-id>")
        return
    identifier = sys.argv[1]
    br = BlastRadius()
    await br.connect()
    result = await br.compute(identifier)
    _print_report(result)


if __name__ == "__main__":
    asyncio.run(main())
