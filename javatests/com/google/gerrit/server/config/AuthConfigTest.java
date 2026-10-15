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

package com.google.gerrit.server.config;

import static com.google.common.truth.Truth.assertThat;

import org.eclipse.jgit.lib.Config;
import org.junit.Test;

public class AuthConfigTest {
  @Test
  public void authTokensFollowTheBasicAuthPolicy() throws Exception {
    assertThat(authConfig("HTTP", null).acceptsAuthTokens()).isTrue();
    assertThat(authConfig("LDAP", null).acceptsAuthTokens()).isFalse();
    assertThat(authConfig("LDAP", "HTTP_LDAP").acceptsAuthTokens()).isTrue();
    assertThat(authConfig("OAUTH", null).acceptsAuthTokens()).isFalse();
  }

  @Test
  public void oauthAcceptsAuthTokensWhenEnabled() throws Exception {
    Config cfg = config("OAUTH", null);
    cfg.setBoolean("auth", null, "oauthAcceptsAuthTokens", true);

    assertThat(new AuthConfig(cfg).acceptsAuthTokens()).isTrue();
  }

  @Test
  public void oauthAcceptsAuthTokensOnlyAppliesToTheOAuthPolicy() throws Exception {
    Config cfg = config("LDAP", null);
    cfg.setBoolean("auth", null, "oauthAcceptsAuthTokens", true);

    assertThat(new AuthConfig(cfg).acceptsAuthTokens()).isFalse();
  }

  private static AuthConfig authConfig(String type, String policy) throws Exception {
    return new AuthConfig(config(type, policy));
  }

  private static Config config(String type, String policy) {
    Config cfg = new Config();
    cfg.setString("auth", null, "type", type);
    if (policy != null) {
      cfg.setString("auth", null, "gitBasicAuthPolicy", policy);
    }
    return cfg;
  }
}
