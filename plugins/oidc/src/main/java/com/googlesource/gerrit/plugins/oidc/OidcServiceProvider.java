// Copyright (C) 2026 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.googlesource.gerrit.plugins.oidc;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.gerrit.common.Nullable;
import com.google.gerrit.extensions.auth.oauth.OAuthServiceProvider;
import com.google.gerrit.extensions.auth.oauth.OAuthToken;
import com.google.gerrit.extensions.auth.oauth.OAuthUserInfo;
import com.google.gerrit.extensions.auth.oauth.OAuthVerifier;
import com.google.gerrit.server.config.CanonicalWebUrl;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import com.googlesource.gerrit.plugins.oidc.Jwt.InvalidTokenException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URLEncoder;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * The web login: the authorization code flow with PKCE against {@code plugin.oidc.issuer}. The user
 * comes from the ID token, whose {@code iss} must be that issuer and whose {@code aud} must be the
 * client.
 */
@Singleton
class OidcServiceProvider implements OAuthServiceProvider {
  private final OidcConfig cfg;
  private final Providers providers;
  private final OidcHttp http;
  private final TokenVerifier verifier;
  private final Identities identities;
  private final Provider<String> canonicalWebUrl;
  private final Supplier<Instant> clock;

  @Inject
  OidcServiceProvider(
      OidcConfig cfg,
      Providers providers,
      OidcHttp http,
      TokenVerifier verifier,
      Identities identities,
      @CanonicalWebUrl @Nullable Provider<String> canonicalWebUrl) {
    this(cfg, providers, http, verifier, identities, canonicalWebUrl, Instant::now);
  }

  OidcServiceProvider(
      OidcConfig cfg,
      Providers providers,
      OidcHttp http,
      TokenVerifier verifier,
      Identities identities,
      Provider<String> canonicalWebUrl,
      Supplier<Instant> clock) {
    this.cfg = cfg;
    this.providers = providers;
    this.http = http;
    this.verifier = verifier;
    this.identities = identities;
    this.canonicalWebUrl = canonicalWebUrl;
    this.clock = clock;
  }

  @Override
  public String getAuthorizationUrl() {
    String endpoint = metadata().authorizationEndpoint().toString();
    return endpoint
        + (endpoint.contains("?") ? "&" : "?")
        + "response_type=code"
        + "&client_id="
        + encode(cfg.clientId())
        + "&redirect_uri="
        + encode(redirectUri())
        + "&scope="
        + encode(cfg.scope());
  }

  @Override
  public boolean usesPkce() {
    return true;
  }

  @Override
  public OAuthToken getAccessToken(OAuthVerifier verifier) {
    if (cfg.clientSecret() == null) {
      throw new IllegalStateException("plugin.oidc.clientSecret must be set for the web login");
    }
    if (Strings.isNullOrEmpty(verifier.getValue())) {
      throw new IllegalArgumentException("The provider returned no authorization code");
    }
    Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "authorization_code");
    form.put("code", verifier.getValue());
    form.put("redirect_uri", redirectUri());
    if (verifier.getCodeVerifier() != null) {
      form.put("code_verifier", verifier.getCodeVerifier());
    }
    JsonObject rsp;
    try {
      rsp =
          http.postForm(
              metadata().tokenEndpoint(),
              ImmutableMap.copyOf(form),
              cfg.clientId(),
              cfg.clientSecret());
    } catch (IOException e) {
      throw new UncheckedIOException("Cannot exchange the authorization code", e);
    }
    String accessToken = Jwt.string(rsp, "access_token");
    String idToken = Jwt.string(rsp, "id_token");
    if (Strings.isNullOrEmpty(accessToken) || Strings.isNullOrEmpty(idToken)) {
      throw new IllegalStateException("Token response has no access_token or id_token");
    }
    long expiresAt = Long.MAX_VALUE;
    JsonElement expiresIn = rsp.get("expires_in");
    if (expiresIn != null
        && expiresIn.isJsonPrimitive()
        && expiresIn.getAsJsonPrimitive().isNumber()) {
      expiresAt = clock.get().plusSeconds(expiresIn.getAsLong()).toEpochMilli();
    }
    // Only the ID token is kept as the raw response: Gerrit caches the token, and the refresh
    // token has no use here.
    return new OAuthToken(accessToken, "", idToken, expiresAt, null);
  }

  @Override
  public OAuthUserInfo getUserInfo(OAuthToken token) throws IOException {
    JsonObject claims;
    try {
      claims = verifier.verify(token.getRaw(), ImmutableSet.of(cfg.issuer()), cfg.clientId());
    } catch (InvalidTokenException e) {
      throw new IOException("Rejected ID token: " + e.getMessage());
    }
    String azp = Jwt.string(claims, "azp");
    if (azp != null && !azp.equals(cfg.clientId())) {
      throw new IOException("ID token was issued to " + azp);
    }
    String username = Jwt.string(claims, cfg.usernameClaim());
    if (Strings.isNullOrEmpty(username)) {
      throw new IOException("ID token has no " + cfg.usernameClaim());
    }
    Identities.Identity id = identities.of(username);
    return new OAuthUserInfo(
        id.externalId(),
        id.username(),
        Strings.emptyToNull(Jwt.string(claims, "email")),
        Strings.emptyToNull(Jwt.string(claims, "name")),
        null);
  }

  @Override
  public String getVersion() {
    return "2.0";
  }

  @Override
  public String getName() {
    return "OpenID Connect";
  }

  private Providers.Metadata metadata() {
    try {
      return providers.metadata(cfg.issuer());
    } catch (IOException e) {
      throw new UncheckedIOException("Cannot read the discovery document of " + cfg.issuer(), e);
    }
  }

  private String redirectUri() {
    String url = canonicalWebUrl.get();
    if (Strings.isNullOrEmpty(url)) {
      throw new IllegalStateException("gerrit.canonicalWebUrl must be set for the web login");
    }
    return (url.endsWith("/") ? url : url + "/") + "oauth";
  }

  private static String encode(String s) {
    return URLEncoder.encode(s, UTF_8);
  }
}
