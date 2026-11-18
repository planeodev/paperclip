// OpenID Connect single sign-on (planeodev fork).
//
// Enabled only when PAPERCLIP_AUTH_OIDC_ISSUER, PAPERCLIP_AUTH_OIDC_CLIENT_ID and PAPERCLIP_AUTH_OIDC_CLIENT_SECRET are
// set. It adds Better Auth's genericOAuth plugin (discovery + PKCE) under the provider id `oidc`, so the callback is
// `<public URL>/api/auth/oauth2/callback/oidc`. Users are created on their first SSO login even when
// `auth.disableSignUp` is true: that flag only closes email/password sign-up, so a closed instance can still admit the
// people its identity provider vouches for.
//
// Group sync (login-time, additive): after every OIDC session the `groups` claim of the stored ID token is mapped
//   - to the instance admin role (PAPERCLIP_AUTH_OIDC_ADMIN_GROUPS, comma-separated), and
//   - to company memberships (PAPERCLIP_AUTH_OIDC_GROUP_MAP, JSON:
//       [{"group":"acme-team","company":"Acme","role":"operator"}]  — company = company id or exact name;
//       role = owner | operator | member, default operator).
// v1 only ADDS roles and memberships; it never removes one (a membership may also have been granted by hand, and
// nothing records its source yet). Removal belongs to the event-driven reconciler (identity-provider events → bus).
import { and, eq, or } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import { authAccounts, companies, companyMemberships, instanceUserRoles } from "@paperclipai/db";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import { ensureHumanRoleDefaultGrants } from "../services/principal-access-compatibility.js";
import { logger } from "../middleware/logger.js";

export const OIDC_PROVIDER_ID = "oidc";
const HUMAN_ROLES = new Set(["owner", "operator", "member"]);

export type OidcGroupMapping = { group: string; company: string; role: string };

export type OidcConfig = {
  issuer: string;
  discoveryUrl: string;
  clientId: string;
  clientSecret: string;
  name: string;
  scopes: string[];
  groupsClaim: string;
  adminGroups: string[];
  groupMap: OidcGroupMapping[];
};

function list(value: string | undefined): string[] {
  return (value ?? "").split(",").map((v) => v.trim()).filter(Boolean);
}

export function parseOidcGroupMap(raw: string | undefined): OidcGroupMapping[] {
  if (!raw?.trim()) return [];
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed)) throw new Error("PAPERCLIP_AUTH_OIDC_GROUP_MAP must be a JSON array");
  return parsed.map((entry, i) => {
    const e = entry as Record<string, unknown>;
    const group = typeof e.group === "string" ? e.group.trim() : "";
    const company = typeof e.company === "string" ? e.company.trim() : "";
    const role = typeof e.role === "string" && e.role.trim() ? e.role.trim() : "operator";
    if (!group || !company) throw new Error(`PAPERCLIP_AUTH_OIDC_GROUP_MAP[${i}] needs "group" and "company"`);
    if (!HUMAN_ROLES.has(role)) throw new Error(`PAPERCLIP_AUTH_OIDC_GROUP_MAP[${i}].role must be owner, operator or member`);
    return { group, company, role };
  });
}

export function readOidcConfig(env: NodeJS.ProcessEnv = process.env): OidcConfig | null {
  const issuer = env.PAPERCLIP_AUTH_OIDC_ISSUER?.trim();
  const clientId = env.PAPERCLIP_AUTH_OIDC_CLIENT_ID?.trim();
  const clientSecret = env.PAPERCLIP_AUTH_OIDC_CLIENT_SECRET?.trim();
  if (!issuer && !clientId && !clientSecret) return null;
  if (!issuer || !clientId || !clientSecret) {
    throw new Error(
      "OIDC is partially configured: PAPERCLIP_AUTH_OIDC_ISSUER, PAPERCLIP_AUTH_OIDC_CLIENT_ID and PAPERCLIP_AUTH_OIDC_CLIENT_SECRET are all required",
    );
  }
  const base = issuer.replace(/\/+$/, "");
  return {
    issuer: base,
    discoveryUrl: env.PAPERCLIP_AUTH_OIDC_DISCOVERY_URL?.trim() || `${base}/.well-known/openid-configuration`,
    clientId,
    clientSecret,
    name: env.PAPERCLIP_AUTH_OIDC_NAME?.trim() || "SSO",
    scopes: list(env.PAPERCLIP_AUTH_OIDC_SCOPES).length ? list(env.PAPERCLIP_AUTH_OIDC_SCOPES) : ["openid", "profile", "email"],
    groupsClaim: env.PAPERCLIP_AUTH_OIDC_GROUPS_CLAIM?.trim() || "groups",
    adminGroups: list(env.PAPERCLIP_AUTH_OIDC_ADMIN_GROUPS),
    groupMap: parseOidcGroupMap(env.PAPERCLIP_AUTH_OIDC_GROUP_MAP),
  };
}

/** What the login page may know: never the client id, secret or group map. */
export function publicOidcInfo(env: NodeJS.ProcessEnv = process.env): { providerId: string; name: string } | null {
  try {
    const cfg = readOidcConfig(env);
    return cfg ? { providerId: OIDC_PROVIDER_ID, name: cfg.name } : null;
  } catch {
    return null;
  }
}

export function buildOidcPlugin(cfg: OidcConfig) {
  return genericOAuth({
    config: [
      {
        providerId: OIDC_PROVIDER_ID,
        name: cfg.name,
        discoveryUrl: cfg.discoveryUrl,
        clientId: cfg.clientId,
        clientSecret: cfg.clientSecret,
        scopes: cfg.scopes,
        pkce: true,
        mapProfileToUser: (profile) => {
          const p = profile as Record<string, unknown>;
          const email = typeof p.email === "string" ? p.email : undefined;
          const name =
            (typeof p.name === "string" && p.name) ||
            (typeof p.preferred_username === "string" && p.preferred_username) ||
            email ||
            "User";
          return { name, ...(email ? { email } : {}), emailVerified: p.email_verified === true };
        },
      },
    ],
  });
}

export function groupsFromIdToken(idToken: string | null | undefined, claim: string): string[] {
  if (!idToken) return [];
  const part = idToken.split(".")[1];
  if (!part) return [];
  try {
    const payload = JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>;
    const value = payload[claim];
    if (Array.isArray(value)) return value.filter((g): g is string => typeof g === "string");
    if (typeof value === "string") return [value];
    return [];
  } catch {
    return [];
  }
}

export type OidcSyncResult = { adminGranted: boolean; membershipsAdded: string[] };

/** Additive sync of one user's groups onto instance-admin and company memberships. */
export async function syncOidcGroups(db: Db, cfg: OidcConfig, userId: string, groups: string[]): Promise<OidcSyncResult> {
  const result: OidcSyncResult = { adminGranted: false, membershipsAdded: [] };
  const have = new Set(groups);

  if (cfg.adminGroups.some((g) => have.has(g))) {
    const existing = await db
      .select({ id: instanceUserRoles.id })
      .from(instanceUserRoles)
      .where(and(eq(instanceUserRoles.userId, userId), eq(instanceUserRoles.role, "instance_admin")))
      .then((rows) => rows[0] ?? null);
    if (!existing) {
      await db.insert(instanceUserRoles).values({ userId, role: "instance_admin" });
      result.adminGranted = true;
    }
  }

  for (const mapping of cfg.groupMap) {
    if (!have.has(mapping.group)) continue;
    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(mapping.company);
    const company = await db
      .select({ id: companies.id })
      .from(companies)
      .where(isUuid ? or(eq(companies.id, mapping.company), eq(companies.name, mapping.company)) : eq(companies.name, mapping.company))
      .then((rows) => rows[0] ?? null);
    if (!company) {
      logger.warn({ group: mapping.group, company: mapping.company }, "OIDC group map names a company that does not exist; skipped");
      continue;
    }
    const membership = await db
      .select({ id: companyMemberships.id })
      .from(companyMemberships)
      .where(
        and(
          eq(companyMemberships.companyId, company.id),
          eq(companyMemberships.principalType, "user"),
          eq(companyMemberships.principalId, userId),
        ),
      )
      .then((rows) => rows[0] ?? null);
    if (membership) continue;
    await db.insert(companyMemberships).values({
      companyId: company.id,
      principalType: "user",
      principalId: userId,
      status: "active",
      membershipRole: mapping.role,
    });
    await ensureHumanRoleDefaultGrants(db, {
      companyId: company.id,
      principalId: userId,
      membershipRole: mapping.role,
      grantedByUserId: null,
    });
    result.membershipsAdded.push(company.id);
  }
  return result;
}

/** Better Auth `databaseHooks.session.create.after`: sync groups for OIDC sessions; never blocks a login. */
export function oidcSessionHook(db: Db, cfg: OidcConfig) {
  return async (session: { userId: string }) => {
    try {
      const account = await db
        .select({ idToken: authAccounts.idToken })
        .from(authAccounts)
        .where(and(eq(authAccounts.userId, session.userId), eq(authAccounts.providerId, OIDC_PROVIDER_ID)))
        .then((rows) => rows[0] ?? null);
      if (!account) return; // not an SSO user (email/password session)
      const groups = groupsFromIdToken(account.idToken, cfg.groupsClaim);
      const res = await syncOidcGroups(db, cfg, session.userId, groups);
      if (res.adminGranted || res.membershipsAdded.length) {
        logger.info({ userId: session.userId, ...res }, "OIDC group sync applied");
      }
    } catch (err) {
      logger.error({ err, userId: session.userId }, "OIDC group sync failed; login continues");
    }
  };
}
