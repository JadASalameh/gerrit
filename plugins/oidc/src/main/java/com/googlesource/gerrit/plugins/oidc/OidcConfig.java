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

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.gerrit.common.Nullable;
import com.google.gerrit.extensions.annotations.PluginName;
import com.google.gerrit.extensions.client.AuthType;
import com.google.gerrit.server.config.ConfigUtil;
import com.google.gerrit.server.config.GerritServerConfig;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.eclipse.jgit.lib.Config;

/** The {@code [plugin "oidc"]} section of {@code gerrit.config} and {@code secure.config}. */
@Singleton
public class OidcConfig {
  static final String DEFAULT_SCOPE = "openid profile email";
  static final String DEFAULT_USERNAME_CLAIM = "preferred_username";
  static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(60);

  private final String issuer;
  private final ImmutableSet<String> acceptedIssuers;
  private final String clientId;
  @Nullable private final String clientSecret;
  private final String audience;
  private final String scope;
  private final String usernameClaim;
  private final Duration clockSkew;
  private final boolean ldapPasswords;

  @Inject
  OidcConfig(@PluginName String pluginName, @GerritServerConfig Config cfg) {
    issuer = required(cfg, pluginName, "issuer");
    ImmutableSet.Builder<String> accepted = ImmutableSet.<String>builder().add(issuer);
    for (String i : cfg.getStringList("plugin", pluginName, "acceptedIssuer")) {
      if (!Strings.isNullOrEmpty(i)) {
        accepted.add(i);
      }
    }
    acceptedIssuers = accepted.build();
    clientId = required(cfg, pluginName, "clientId");
    clientSecret = Strings.emptyToNull(cfg.getString("plugin", pluginName, "clientSecret"));
    audience = value(cfg, pluginName, "audience", clientId);
    scope = value(cfg, pluginName, "scope", DEFAULT_SCOPE);
    usernameClaim = value(cfg, pluginName, "usernameClaim", DEFAULT_USERNAME_CLAIM);
    clockSkew =
        Duration.ofSeconds(
            ConfigUtil.getTimeUnit(
                cfg,
                "plugin",
                pluginName,
                "clockSkew",
                DEFAULT_CLOCK_SKEW.toSeconds(),
                TimeUnit.SECONDS));
    ldapPasswords = ldapPasswordsEnabled(pluginName, cfg);
  }

  /**
   * Whether {@code login} checks passwords against {@code ldap.server}: the plugin option is on
   * (the default), the site uses OAuth (an LDAP site already binds the LDAP helper) and a server is
   * set.
   */
  static boolean ldapPasswordsEnabled(String pluginName, Config cfg) {
    return cfg.getBoolean("plugin", pluginName, "ldapPasswords", true)
        && cfg.getEnum("auth", null, "type", AuthType.OPENID) == AuthType.OAUTH
        && !Strings.isNullOrEmpty(cfg.getString("ldap", null, "server"));
  }

  /**
   * The issuer whose discovery document configures the web login, exactly as tokens name it in
   * {@code iss}.
   */
  public String issuer() {
    return issuer;
  }

  /** Issuers whose tokens Git and REST requests may carry; always includes {@link #issuer()}. */
  public ImmutableSet<String> acceptedIssuers() {
    return acceptedIssuers;
  }

  public String clientId() {
    return clientId;
  }

  @Nullable
  public String clientSecret() {
    return clientSecret;
  }

  /** The {@code aud} a token must name to authenticate Git and REST requests. */
  public String audience() {
    return audience;
  }

  public String scope() {
    return scope;
  }

  public String usernameClaim() {
    return usernameClaim;
  }

  public Duration clockSkew() {
    return clockSkew;
  }

  public boolean ldapPasswords() {
    return ldapPasswords;
  }

  private static String required(Config cfg, String pluginName, String name) {
    String v = cfg.getString("plugin", pluginName, name);
    if (Strings.isNullOrEmpty(v)) {
      throw new IllegalStateException(String.format("plugin.%s.%s must be set", pluginName, name));
    }
    return v;
  }

  private static String value(Config cfg, String pluginName, String name, String defaultValue) {
    String v = cfg.getString("plugin", pluginName, name);
    return Strings.isNullOrEmpty(v) ? defaultValue : v;
  }
}
