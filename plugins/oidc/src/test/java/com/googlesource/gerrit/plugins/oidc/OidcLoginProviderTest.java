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

import static com.google.common.truth.Truth.assertThat;
import static com.googlesource.gerrit.plugins.oidc.FakeProvider.ISSUER;
import static com.googlesource.gerrit.plugins.oidc.FakeProvider.OTHER_ISSUER;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.gerrit.entities.Account;
import com.google.gerrit.extensions.auth.oauth.OAuthUserInfo;
import com.google.gerrit.index.query.Predicate;
import com.google.gerrit.server.account.AccountCache;
import com.google.gerrit.server.account.AccountState;
import com.google.gerrit.server.account.AuthTokenVerifier;
import com.google.gerrit.server.account.externalids.ExternalId;
import com.google.gerrit.server.auth.AuthenticationUnavailableException;
import com.google.gerrit.server.config.AuthConfig;
import com.google.gerrit.server.query.account.InternalAccountQuery;
import java.io.IOException;
import java.time.Instant;
import java.util.Optional;
import org.eclipse.jgit.lib.Config;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;

public class OidcLoginProviderTest {
  private static final Account.Id ACCOUNT = Account.id(1000);

  private FakeProvider idp;
  private AccountCache accountCache;
  private InternalAccountQuery query;
  private AuthTokenVerifier authTokens;
  private AuthConfig authConfig;
  private OidcLoginProvider.Passwords passwords;

  @Before
  public void setUp() throws Exception {
    idp = new FakeProvider();
    accountCache = mock(AccountCache.class);
    query = mock(InternalAccountQuery.class);
    when(query.query(ArgumentMatchers.<Predicate<AccountState>>any()))
        .thenReturn(ImmutableList.of());
    authTokens = mock(AuthTokenVerifier.class);
    authConfig = mock(AuthConfig.class);
    passwords = mock(OidcLoginProvider.Passwords.class);
    when(accountCache.getByUsername(anyString())).thenReturn(Optional.empty());
  }

  @Test
  public void basicAuthWithTokenOfThatUser() throws Exception {
    // First signed in through LDAP as "JDoe".
    account("jdoe", true, gerrit("JDoe"));

    OAuthUserInfo info = provider(true).login("jdoe", token(ISSUER, "jdoe", "gerrit"));

    assertThat(info.getExternalId()).isEqualTo("gerrit:JDoe");
    assertThat(info.getEmailAddress()).isNull();
    assertThat(info.getDisplayName()).isNull();
    verify(passwords, never()).check(anyString(), anyString());
  }

  @Test
  public void basicAuthWithTokenOfAnotherUserIsRejected() throws Exception {
    account("jdoe", true, gerrit("jdoe"));

    IOException e =
        assertThrows(
            IOException.class,
            () -> provider(true).login("jdoe", token(ISSUER, "admin", "gerrit")));
    assertThat(e).hasMessageThat().contains("Token of admin sent as jdoe");
  }

  @Test
  public void bearerTokenFromAnAcceptedIssuer() throws Exception {
    account("jdoe", true, gerrit("jdoe"));

    OAuthUserInfo info = provider(true).login(null, token(OTHER_ISSUER, "jdoe", "gerrit"));

    assertThat(info.getExternalId()).isEqualTo("gerrit:jdoe");
    assertThat(info.getUserName()).isEqualTo("jdoe");
  }

  @Test
  public void bearerTokenFindsAccountWhoseUsernameHasAnotherCase() throws Exception {
    AccountState a = state("JDoe", true, gerrit("JDoe"));
    when(query.query(ArgumentMatchers.<Predicate<AccountState>>any()))
        .thenReturn(ImmutableList.of(a));

    OAuthUserInfo info = provider(true).login(null, token(ISSUER, "jdoe", "gerrit"));

    assertThat(info.getExternalId()).isEqualTo("gerrit:JDoe");
    assertThat(info.getUserName()).isEqualTo("JDoe");
  }

  @Test
  public void bearerTokenOfServiceAccountCreatedThroughRest() throws Exception {
    account("svc-bot", true, ExternalId.create(key("username", "svc-bot"), ACCOUNT, null, null));

    OAuthUserInfo info = provider(true).login(null, token(ISSUER, "svc-bot", "gerrit"));

    assertThat(info.getExternalId()).isEqualTo("username:svc-bot");
  }

  @Test
  public void bearerTokenOfUnknownOrInactiveUserIsRejected() throws Exception {
    assertThrows(
        IOException.class, () -> provider(true).login(null, token(ISSUER, "nobody", "gerrit")));

    account("gone", false, gerrit("gone"));
    assertThrows(
        IOException.class, () -> provider(true).login(null, token(ISSUER, "gone", "gerrit")));
  }

  @Test
  public void tokenForAnotherAudienceIsRejected() throws Exception {
    account("jdoe", true, gerrit("jdoe"));

    IOException e =
        assertThrows(
            IOException.class, () -> provider(true).login(null, token(ISSUER, "jdoe", "other")));
    assertThat(e).hasMessageThat().contains("not meant for gerrit");
  }

  @Test
  public void bearerCredentialThatIsNotATokenIsRejected() throws Exception {
    assertThrows(IOException.class, () -> provider(true).login(null, "hunter2"));
    verify(passwords, never()).check(any(), any());
  }

  @Test
  public void gerritAuthTokenWhenAccepted() throws Exception {
    account("jdoe", true, gerrit("jdoe"));
    when(authTokens.checkToken(ACCOUNT, "gerrit-token")).thenReturn(true);

    assertThat(provider(true).login("jdoe", "gerrit-token").getExternalId())
        .isEqualTo("gerrit:jdoe");
    verify(passwords, never()).check(any(), any());
  }

  @Test
  public void gerritAuthTokenIgnoredWhenNotAccepted() throws Exception {
    account("jdoe", true, gerrit("jdoe"));
    when(authTokens.checkToken(ACCOUNT, "gerrit-token")).thenReturn(true);

    assertThrows(IOException.class, () -> provider(false).login("jdoe", "gerrit-token"));
    verify(authTokens, never()).checkToken(any(), any());
  }

  @Test
  public void ldapPassword() throws Exception {
    account("jdoe", true, gerrit("jdoe"));
    when(passwords.check("jdoe", "s3cret")).thenReturn(true);

    assertThat(provider(true).login("jdoe", "s3cret").getExternalId()).isEqualTo("gerrit:jdoe");
  }

  @Test
  public void wrongPasswordIsRejected() throws Exception {
    account("jdoe", true, gerrit("jdoe"));

    assertThrows(IOException.class, () -> provider(true).login("jdoe", "wrong"));
  }

  @Test
  public void unreachableDirectoryIsAnError() throws Exception {
    account("jdoe", true, gerrit("jdoe"));
    doThrow(new AuthenticationUnavailableException("down", new IOException()))
        .when(passwords)
        .check("jdoe", "s3cret");

    IOException e = assertThrows(IOException.class, () -> provider(true).login("jdoe", "s3cret"));
    assertThat(e).hasCauseThat().isInstanceOf(AuthenticationUnavailableException.class);
  }

  private OidcLoginProvider provider(boolean acceptsAuthTokens) {
    doReturn(acceptsAuthTokens).when(authConfig).acceptsAuthTokens();
    OidcConfig cfg = config();
    TokenVerifier verifier = new TokenVerifier(new Providers(idp), cfg);
    return new OidcLoginProvider(
        cfg,
        verifier,
        new Identities(accountCache, () -> query),
        authTokens,
        authConfig,
        passwords);
  }

  static OidcConfig config() {
    Config c = new Config();
    c.setString("plugin", "oidc", "issuer", ISSUER);
    c.setString("plugin", "oidc", "acceptedIssuer", OTHER_ISSUER);
    c.setString("plugin", "oidc", "clientId", "gerrit");
    c.setString("plugin", "oidc", "clientSecret", "client-secret");
    return new OidcConfig("oidc", c);
  }

  private String token(String issuer, String username, String aud) throws Exception {
    return FakeProvider.sign(
        idp.key(issuer),
        "{\"iss\": \""
            + issuer
            + "\", \"aud\": \""
            + aud
            + "\", \"exp\": "
            + (Instant.now().getEpochSecond() + 300)
            + ", \"preferred_username\": \""
            + username
            + "\"}");
  }

  private void account(String username, boolean active, ExternalId... ids) {
    when(accountCache.getByUsername(username))
        .thenReturn(Optional.of(state(username, active, ids)));
  }

  static AccountState state(String username, boolean active, ExternalId... ids) {
    ImmutableList<ExternalId> all =
        ImmutableList.<ExternalId>builder()
            .add(ids)
            .add(ExternalId.create(key("username", username), ACCOUNT, null, null))
            .build()
            .stream()
            .distinct()
            .collect(ImmutableList.toImmutableList());
    return AccountState.forAccount(
        Account.builder(ACCOUNT, Instant.EPOCH).setInactive(!active).build(), all);
  }

  static ExternalId gerrit(String id) {
    return ExternalId.create(key("gerrit", id), ACCOUNT, id.toLowerCase() + "@example.com", null);
  }

  static ExternalId.Key key(String scheme, String id) {
    return ExternalId.Key.create(scheme, id, false);
  }
}
