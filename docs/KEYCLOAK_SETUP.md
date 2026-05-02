# Keycloak Setup for OBP-MCP

This document is written for system administrators configuring Keycloak so that
it can issue tokens accepted by the OBP-MCP server.

The MCP server is working with OBP-OIDC; this document covers the additional
configuration needed to make Keycloak work alongside (or instead of) OBP-OIDC.

---

## TL;DR — What has to line up

For Keycloak to work with OBP-MCP, **all** of the following must be true. Each
item below is the most frequent reason Keycloak tokens get rejected with `401
Unauthorized` / `invalid_token`.

1. The `iss` claim in every Keycloak access token must match **exactly** what
   the MCP server has configured as `KEYCLOAK_REALM_URL` (character-for-character).
2. The `aud` (audience) claim must contain an audience the MCP server accepts
   (or the MCP server must be configured with no audience requirement).
3. The token must be signed with `RS256` (the MCP server's default) — or the
   server must be explicitly configured for the realm's signing algorithm.
4. The token's `kid` (key ID) must be present in the realm's JWKS endpoint at
   the moment of validation.
5. The client must request and receive the scopes the MCP server requires
   (default: `openid profile email`).
6. Server clocks on Keycloak and the MCP host must be in sync (NTP).

Items 1–5 are Keycloak-side configuration; item 6 is infrastructure.

---

## 1. MCP server environment

On the MCP server host, set these in `.env`:

```env
ENABLE_OAUTH=true

# If the MCP server should accept ONLY Keycloak tokens:
AUTH_PROVIDER=keycloak
KEYCLOAK_REALM_URL=https://<keycloak-host>/realms/<realm-name>

# OR — if it should accept tokens from BOTH Keycloak and OBP-OIDC:
AUTH_PROVIDER=bearer-only
KEYCLOAK_REALM_URL=https://<keycloak-host>/realms/<realm-name>
OBP_OIDC_ISSUER_URL=https://<obp-oidc-host>/obp-oidc
```

**Critical:** `KEYCLOAK_REALM_URL` must match the `iss` claim that Keycloak
actually puts in its tokens, byte-for-byte. Pitfalls:

- **Trailing slash** — `/realms/foo` vs `/realms/foo/` are different values.
- **Hostname** — if Keycloak is accessed as `https://sso.example.com` externally
  but `http://keycloak:8080` internally, tokens carry whichever URL the client
  used to authenticate. The MCP server must be configured with the same one.
- **Scheme / port** — `http://` vs `https://`, and any non-default port, all
  count as part of the string.

To verify: issue a test token, paste it into https://jwt.io, and copy the `iss`
claim verbatim into `KEYCLOAK_REALM_URL`.

The MCP server will fetch keys from
`{KEYCLOAK_REALM_URL}/protocol/openid-connect/certs` — make sure that URL is
reachable from the MCP host. (`curl $KEYCLOAK_REALM_URL/protocol/openid-connect/certs`
should return a JSON document with a `keys` array.)

---

## 2. Keycloak realm configuration

### 2.1 Realm signing key

**Realm settings → Keys → Active**

Confirm the realm has an active **RS256** signing key. If the realm was built
with a different default (e.g. `PS256`, `ES256`), either:

- switch the realm's active key to RS256, **or**
- set the MCP server to the realm's algorithm (requires a code change in
  `auth.py` — contact the MCP maintainer if this is needed).

### 2.2 Realm issuer URL (frontendUrl)

**Realm settings → General → Frontend URL**

Set `frontendUrl` to the **external** URL of Keycloak — the one clients use to
log in (e.g. `https://sso.example.com`). This is what appears in the `iss`
claim. If frontendUrl is left blank, Keycloak uses whatever host the client hit
first, which can produce mixed `iss` values and break MCP validation
non-deterministically.

---

## 3. Client configuration

For each MCP client that will talk to OBP-MCP:

**Clients → [client-id] → Settings**

- **Client Protocol:** `openid-connect`
- **Access Type:** `confidential` (for server-to-server) or `public` (for PKCE
  browser clients)
- **Valid Redirect URIs:** whatever the MCP client needs
- **Standard Flow / Direct Access Grants / Service Accounts:** enable whichever
  flow the client uses

### 3.1 Scopes (MUST be on the default list, not optional)

**Clients → [client-id] → Client Scopes → Setup**

The MCP server defaults to requiring `openid`, `profile`, and `email` in the
token. Keycloak only includes a scope in the access token if it's on the
client's **default** scope list — optional scopes only appear when the client
explicitly requests them.

Move these from "Assigned optional client scopes" to **"Assigned default client
scopes"**:

- `openid`
- `profile`
- `email`

Verify afterward: the `scope` claim in a test access token should contain all
three.

### 3.2 Audience mapper — the most common gotcha

By default, Keycloak issues access tokens with `aud: "account"`, not the
client's own ID. If the MCP server is deployed with an `audience` configured,
validation will fail with an audience mismatch.

**Two options:**

**Option A — Don't enforce audience (simpler).**
Leave the MCP server's audience unset. Tokens validate based on issuer and
signature only. This is the default if you don't pass `audience=` anywhere.

**Option B — Add an audience mapper (stricter).**
If you want the MCP server to verify `aud` contains a specific value:

1. **Clients → [client-id] → Client Scopes → [client-id]-dedicated → Mappers
   → Add mapper → By configuration → Audience**
2. **Name:** `obp-mcp-audience`
3. **Included Custom Audience:** `obp-mcp` (or any string agreed with the MCP
   maintainer)
4. **Add to ID token:** off
5. **Add to access token:** **on**
6. Save.

Then configure the MCP server to expect that same audience. (This currently
requires a code change — `JWTVerifier(... audience="obp-mcp")` in `auth.py`.
Contact the MCP maintainer to wire up an env var for this if needed.)

---

## 4. Dynamic Client Registration (full OAuth mode only)

Only relevant when `AUTH_PROVIDER=keycloak` (not `bearer-only`). In that mode
the MCP server exposes a `/register` proxy so MCP clients (VS Code, Claude
Desktop, etc.) can register themselves.

### 4.1 Enable anonymous DCR

**Realm settings → Client registration policies → Anonymous access policies**

Review which policies are applied to anonymous DCR. At minimum, the
`Trusted Hosts` policy must include the MCP server's host (or be relaxed) so
the MCP server can forward registration requests.

### 4.2 Keycloak version note — `token_endpoint_auth_method` workaround

Older Keycloak versions ignore the client's requested
`token_endpoint_auth_method` during DCR and always return `client_secret_basic`,
which breaks MCP clients that require `client_secret_post` (per RFC 9110).

This was fixed in Keycloak **PR #45309** (merged 12 January 2026). The MCP
server includes a minimal DCR proxy that rewrites the response for older
versions — no action needed from you, but upgrading Keycloak to a build that
includes #45309 lets you remove the proxy in the future.

---

## 5. Verification checklist

Run these from the MCP server host after configuration:

```bash
# 1. JWKS is reachable and contains a key
curl -fsS "$KEYCLOAK_REALM_URL/protocol/openid-connect/certs" | jq '.keys[].kid'

# 2. OIDC discovery works
curl -fsS "$KEYCLOAK_REALM_URL/.well-known/openid-configuration" | jq .issuer

# 3. Issue a test token (replace placeholders)
ACCESS_TOKEN=$(curl -fsS -X POST \
  "$KEYCLOAK_REALM_URL/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=<client-id>" \
  -d "client_secret=<client-secret>" \
  -d "username=<test-user>" \
  -d "password=<test-password>" \
  -d "scope=openid profile email" | jq -r .access_token)

# 4. Decode it (payload only, no verification) and inspect
echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{iss, aud, exp, scope}'

# 5. Confirm iss matches KEYCLOAK_REALM_URL exactly
echo "Expected iss: $KEYCLOAK_REALM_URL"
```

A healthy token looks like:

```json
{
  "iss": "https://sso.example.com/realms/obp-mcp",
  "aud": "account",
  "exp": 1745341830,
  "scope": "openid profile email"
}
```

---

## 6. Troubleshooting — reading the MCP server logs

When a token is rejected, the MCP server now emits a `JWT validation failed —
diagnostics` block at WARNING level. Example:

```
═══ JWT validation failed — diagnostics ═══
  Token header: kid='abc123', alg='RS256', typ='JWT'
  Token payload: iss='https://sso.example.com/realms/obp-mcp/', aud='account', ...
  Token timing : iat=1745341200, exp=1745344800, now=1745341500, expired=False
  Token scope  : 'openid profile'
  Expected     : issuer='https://sso.example.com/realms/obp-mcp', audience=None, ...
  ✗ ISSUER MISMATCH: token iss='...realms/obp-mcp/' not in expected ['...realms/obp-mcp']
  JWKS https://sso.example.com/realms/obp-mcp/protocol/openid-connect/certs currently publishes kids: ['abc123', 'def456']
═══ end diagnostics ═══
```

How to read each line:

| Log line | What it means | Typical fix |
|---|---|---|
| `✗ ISSUER MISMATCH` | Token's `iss` doesn't match `KEYCLOAK_REALM_URL` | Align the two — usually a trailing-slash, scheme, or hostname difference. See §1. |
| `✗ KID MISMATCH` | Token was signed with a key ID no longer in the JWKS | Key rotation — the client must re-authenticate to get a fresh token. If this is happening repeatedly, something is caching old tokens. |
| `✗ AUDIENCE MISMATCH` | Token's `aud` doesn't contain the expected value | Add an audience mapper (§3.2) or remove the audience requirement on the MCP server. |
| `✗ ALGORITHM MISMATCH` | Realm signs with something other than RS256 | Switch realm key to RS256 (§2.1) or reconfigure MCP server. |
| `expired=True` | Token is past `exp` | Client must refresh. If clocks are in sync and tokens are immediately expired, check NTP on both hosts. |
| `Token scope` missing a required value | Client didn't get the required scopes | Move scopes from Optional to Default on the client (§3.1). |

---

## 7. Summary of what Keycloak must provide

A single, deployable configuration checklist:

- [ ] Realm has an active RS256 signing key
- [ ] Realm `frontendUrl` is set to the external Keycloak URL
- [ ] JWKS endpoint `{realm}/protocol/openid-connect/certs` is reachable from the MCP host
- [ ] Client has `openid`, `profile`, `email` on its **default** client scope list
- [ ] Either no audience enforcement, or an audience mapper with a value the MCP server expects
- [ ] (DCR only) Anonymous client registration policy allows the MCP server host
- [ ] NTP enabled on Keycloak and MCP hosts
- [ ] `KEYCLOAK_REALM_URL` in the MCP server's `.env` matches the `iss` claim exactly
