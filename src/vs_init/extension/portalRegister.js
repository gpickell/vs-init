// Ported from vss-prime's agolregister.py (_portal_call/_portal_post,
// _username, _add_application_item, _register_oauth_app,
// _update_oauth_app). The exact request/response shape of
// addItem/registerApp has never been confirmed against a real portal --
// see agolToken.js's header comment and that file's own for the full
// rationale. app_id is hedged across a couple of plausible response
// field spellings for exactly that reason.

const APP_TYPE = "native"; // same choice vss-prime made: public client, no secret

async function portalGet(portal, relativePath, params) {
  const query = new URLSearchParams(params).toString();
  const response = await fetch(`${portal}/sharing/rest/${relativePath}?${query}`);
  return response.json();
}

// POST is required for state-changing calls (addItem, registerApp) --
// the ArcGIS REST API rejects them over GET with a 405 (messageCode
// GWM_0005, "Method not supported").
async function portalPost(portal, relativePath, params) {
  const response = await fetch(`${portal}/sharing/rest/${relativePath}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
  });
  return response.json();
}

async function resolveUsername(portal, token) {
  const data = await portalGet(portal, "community/self", { f: "json", token });
  if (!data.username) {
    throw new Error(`Could not resolve the signed-in username: ${JSON.stringify(data)}`);
  }
  return data.username;
}

/** Creates a new, empty Application-type item owned by the signed-in
 * user -- the item registerOAuthApp then attaches OAuth info to. */
async function addApplicationItem(portal, token, username, title) {
  const data = await portalPost(portal, `content/users/${encodeURIComponent(username)}/addItem`, {
    f: "json",
    token,
    title,
    type: "Application",
  });
  if (!data.id) {
    throw new Error(`addItem did not return an id: ${JSON.stringify(data)}`);
  }
  return data.id;
}

/** Attaches OAuth info to the item -- a public/native client (no
 * secret), scoped to redirectUris. */
async function registerOAuthApp(portal, token, itemId, redirectUris) {
  return portalPost(portal, "oauth2/registerApp", {
    f: "json",
    token,
    itemId,
    appType: APP_TYPE,
    redirect_uris: JSON.stringify(redirectUris),
  });
}

/** Refreshes redirect URIs on an already-registered app, rather than
 * creating a duplicate Application item every time. */
async function updateOAuthApp(portal, token, appId, redirectUris) {
  return portalPost(portal, `oauth2/apps/${encodeURIComponent(appId)}/update`, {
    f: "json",
    token,
    redirect_uris: JSON.stringify(redirectUris),
  });
}

/** Pure-ish pluck: the app id shows up under a couple of plausible
 * spellings depending on portal version, per vss-prime's own hedge. */
function extractAppId(info) {
  return info.client_id || info.clientId || info.client || null;
}

module.exports = { resolveUsername, addApplicationItem, registerOAuthApp, updateOAuthApp, extractAppId };
