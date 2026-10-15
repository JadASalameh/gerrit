Signs users in with an OpenID Connect provider, and authenticates Git over
HTTP and REST API requests with the provider's tokens, Gerrit authentication
tokens or LDAP passwords.

The web login is the authorization code flow with PKCE. The user is read from
the ID token: `preferred_username` (see `plugin.@PLUGIN@.usernameClaim`) is
the Gerrit username, `email` and `name` the account's email and full name.

Accounts keep the identity LDAP logins give them, `gerrit:<username>`: a site
can move from `auth.type = LDAP` to this plugin, and back, without creating new
accounts or changing existing ones. When no account has the username exactly,
the only account that has it in another case is used.

Git over HTTP and REST API requests can send, either as the password of Basic
authentication or as a Bearer token:

* an access token from an accepted issuer whose `aud` includes
  `plugin.@PLUGIN@.audience`. With Basic authentication, the username must be
  the token's;
* a Gerrit authentication token, when `auth.oauthAcceptsAuthTokens` is set;
* the user's LDAP password, when `ldap.server` is set. The password is checked
  by binding as the user, as `auth.type = LDAP` does; group membership is not
  read from LDAP.

Only existing, active accounts authenticate this way, and authenticating never
changes the account. Accounts are created by the web login.

Logging out ends the Gerrit session only.
