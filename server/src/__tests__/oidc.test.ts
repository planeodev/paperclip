import { describe, expect, it } from "vitest";
import {
  groupsFromIdToken,
  OIDC_PROVIDER_ID,
  parseOidcGroupMap,
  publicOidcInfo,
  readOidcConfig,
} from "../auth/oidc.js";

const base = {
  PAPERCLIP_AUTH_OIDC_ISSUER: "https://auth.example.test/application/o/paperclip-acme/",
  PAPERCLIP_AUTH_OIDC_CLIENT_ID: "client-id",
  PAPERCLIP_AUTH_OIDC_CLIENT_SECRET: "client-secret",
};

function jwt(payload: Record<string, unknown>): string {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${enc({ alg: "RS256" })}.${enc(payload)}.signature`;
}

describe("readOidcConfig", () => {
  it("is disabled when nothing is set", () => {
    expect(readOidcConfig({})).toBeNull();
  });

  it("fails loudly on a partial configuration", () => {
    expect(() => readOidcConfig({ PAPERCLIP_AUTH_OIDC_ISSUER: base.PAPERCLIP_AUTH_OIDC_ISSUER })).toThrow(/partially configured/);
  });

  it("derives discovery from the issuer and applies defaults", () => {
    const cfg = readOidcConfig({ ...base });
    expect(cfg).toMatchObject({
      issuer: "https://auth.example.test/application/o/paperclip-acme",
      discoveryUrl: "https://auth.example.test/application/o/paperclip-acme/.well-known/openid-configuration",
      name: "SSO",
      scopes: ["openid", "profile", "email"],
      groupsClaim: "groups",
      adminGroups: [],
      groupMap: [],
    });
  });

  it("reads admin groups and the group map", () => {
    const cfg = readOidcConfig({
      ...base,
      PAPERCLIP_AUTH_OIDC_NAME: "authentik",
      PAPERCLIP_AUTH_OIDC_ADMIN_GROUPS: "platform-admins, planeo-admins",
      PAPERCLIP_AUTH_OIDC_GROUP_MAP: '[{"group":"acme-team","company":"Acme"},{"group":"acme-owners","company":"Acme","role":"owner"}]',
    });
    expect(cfg?.name).toBe("authentik");
    expect(cfg?.adminGroups).toEqual(["platform-admins", "planeo-admins"]);
    expect(cfg?.groupMap).toEqual([
      { group: "acme-team", company: "Acme", role: "operator" },
      { group: "acme-owners", company: "Acme", role: "owner" },
    ]);
  });
});

describe("parseOidcGroupMap", () => {
  it("rejects unknown roles and missing fields", () => {
    expect(() => parseOidcGroupMap('[{"group":"g","company":"c","role":"root"}]')).toThrow(/owner, operator or member/);
    expect(() => parseOidcGroupMap('[{"group":"g"}]')).toThrow(/needs "group" and "company"/);
    expect(() => parseOidcGroupMap('{"group":"g"}')).toThrow(/JSON array/);
  });
});

describe("publicOidcInfo", () => {
  it("exposes only the provider id and display name", () => {
    expect(publicOidcInfo({ ...base, PAPERCLIP_AUTH_OIDC_NAME: "authentik" })).toEqual({ providerId: OIDC_PROVIDER_ID, name: "authentik" });
    expect(publicOidcInfo({})).toBeNull();
  });

  it("never throws for the health endpoint, even when misconfigured", () => {
    expect(publicOidcInfo({ PAPERCLIP_AUTH_OIDC_CLIENT_ID: "only-this" })).toBeNull();
  });
});

describe("groupsFromIdToken", () => {
  it("reads an array or a single-string claim", () => {
    expect(groupsFromIdToken(jwt({ groups: ["a", "b", 3] }), "groups")).toEqual(["a", "b"]);
    expect(groupsFromIdToken(jwt({ roles: "admin" }), "roles")).toEqual(["admin"]);
  });

  it("returns no groups for a missing claim, a missing token or garbage", () => {
    expect(groupsFromIdToken(jwt({ sub: "x" }), "groups")).toEqual([]);
    expect(groupsFromIdToken(null, "groups")).toEqual([]);
    expect(groupsFromIdToken("not-a-jwt", "groups")).toEqual([]);
    expect(groupsFromIdToken("a.!!!.c", "groups")).toEqual([]);
  });
});
