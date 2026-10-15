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

package com.google.gerrit.httpd.auth.oauth;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import com.google.common.base.Splitter;
import com.google.common.io.BaseEncoding;
import com.google.gerrit.auth.oauth.OAuthTokenCache;
import com.google.gerrit.entities.Account;
import com.google.gerrit.extensions.auth.oauth.OAuthServiceProvider;
import com.google.gerrit.extensions.auth.oauth.OAuthToken;
import com.google.gerrit.extensions.auth.oauth.OAuthUserInfo;
import com.google.gerrit.extensions.auth.oauth.OAuthVerifier;
import com.google.gerrit.extensions.registration.DynamicItem;
import com.google.gerrit.httpd.CanonicalWebUrl;
import com.google.gerrit.httpd.WebSession;
import com.google.gerrit.server.IdentifiedUser;
import com.google.gerrit.server.account.AccountManager;
import com.google.gerrit.server.account.AuthRequest;
import com.google.gerrit.server.account.AuthResult;
import com.google.gerrit.server.account.externalids.ExternalIdKeyFactory;
import com.google.gerrit.server.config.AuthConfig;
import com.google.gerrit.util.http.testutil.FakeHttpServletRequest;
import com.google.gerrit.util.http.testutil.FakeHttpServletResponse;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * The login started on one node finishes on another: each test builds a fresh {@link OAuthSession}
 * for the callback, as a second node with an empty servlet session would.
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuthSessionTest {
  private static final byte[] KEY = "0123456789abcdef0123456789abcdef".getBytes(UTF_8);
  private static final Account.Id ACCOUNT = Account.id(1000);

  @Mock private DynamicItem<WebSession> webSessionItem;
  @Mock private WebSession webSession;
  @Mock private AccountManager accountManager;
  @Mock private CanonicalWebUrl canonicalWebUrl;
  @Mock private OAuthTokenCache tokenCache;
  @Mock private AuthConfig authConfig;

  private ExternalIdKeyFactory extIdKeyFactory;
  private AuthRequest.Factory authRequestFactory;
  private FakeProvider provider;

  @Before
  public void setUp() throws Exception {
    extIdKeyFactory = new ExternalIdKeyFactory(new ExternalIdKeyFactory.ConfigImpl(authConfig));
    authRequestFactory = new AuthRequest.Factory(extIdKeyFactory);
    provider = new FakeProvider(true);
  }

  @Test
  public void callbackCompletesOnAnotherNode() throws Exception {
    stubSuccessfulLogin();
    Started started = start(newSession(KEY));

    FakeHttpServletResponse res = new FakeHttpServletResponse();
    boolean done =
        newSession(KEY).login(callback(started.state(), started.cookie()), res, provider);

    assertThat(done).isTrue();
    assertThat(res.getStatus()).isEqualTo(HttpServletResponse.SC_FOUND);
    assertThat(res.getHeader("Location")).isEqualTo("https://gerrit.example.com/dashboard");
    assertThat(res.getHeaders("Set-Cookie")).contains(OAuthLoginStateCodec.COOKIE + "=");
    assertThat(challenge(provider.verifier.getCodeVerifier())).isEqualTo(started.challenge());
    assertThat(provider.verifier.getValue()).isEqualTo("the-code");
    verify(webSession).login(any(), any(Boolean.class));
  }

  @Test
  public void authorizationUrlCarriesStateAndS256Challenge() throws Exception {
    Started started = start(newSession(KEY));

    assertThat(started.params()).containsKey("state");
    assertThat(started.params()).containsEntry("code_challenge_method", "S256");
    assertThat(started.challenge()).hasLength(43);
  }

  @Test
  public void eachLoginGetsItsOwnStateAndVerifier() throws Exception {
    OAuthSession session = newSession(KEY);

    Started first = start(session);
    Started second = start(session);

    assertThat(second.state()).isNotEqualTo(first.state());
    assertThat(second.challenge()).isNotEqualTo(first.challenge());
  }

  @Test
  public void callbackWithAnotherStateIsRejected() throws Exception {
    Started started = start(newSession(KEY));

    FakeHttpServletResponse res = new FakeHttpServletResponse();
    boolean done = newSession(KEY).login(callback("forged", started.cookie()), res, provider);

    assertThat(done).isFalse();
    assertThat(res.getStatus()).isEqualTo(HttpServletResponse.SC_NOT_FOUND);
    assertThat(provider.verifier).isNull();
  }

  @Test
  public void cookieSignedWithAnotherKeyIsIgnored() throws Exception {
    Started started = start(newSession(KEY));

    FakeHttpServletResponse res = new FakeHttpServletResponse();
    boolean done =
        newSession("fedcba9876543210fedcba9876543210".getBytes(UTF_8))
            .login(callback(started.state(), started.cookie()), res, provider);

    assertThat(done).isFalse();
    assertThat(res.getStatus()).isEqualTo(HttpServletResponse.SC_NOT_FOUND);
    verify(accountManager, never()).authenticate(any());
  }

  @Test
  public void withoutAKeyTheLoginStaysInTheServletSession() throws Exception {
    stubSuccessfulLogin();
    OAuthSession session = newSession(new byte[0]);
    Started started = start(session);
    assertThat(started.cookie()).isNull();

    FakeHttpServletResponse elsewhere = new FakeHttpServletResponse();
    assertThat(newSession(new byte[0]).login(callback(started.state(), null), elsewhere, provider))
        .isFalse();
    assertThat(elsewhere.getStatus()).isEqualTo(HttpServletResponse.SC_NOT_FOUND);

    FakeHttpServletResponse sameNode = new FakeHttpServletResponse();
    assertThat(session.login(callback(started.state(), null), sameNode, provider)).isTrue();
    assertThat(challenge(provider.verifier.getCodeVerifier())).isEqualTo(started.challenge());
  }

  @Test
  public void callbackCannotBeReplayedInTheSameSession() throws Exception {
    stubSuccessfulLogin();
    OAuthSession session = newSession(KEY);
    Started started = start(session);
    assertThat(
            session.login(
                callback(started.state(), started.cookie()),
                new FakeHttpServletResponse(),
                provider))
        .isTrue();
    provider.verifier = null;

    FakeHttpServletResponse replay = new FakeHttpServletResponse();
    assertThat(session.login(callback(started.state(), null), replay, provider)).isFalse();
    assertThat(replay.getStatus()).isEqualTo(HttpServletResponse.SC_NOT_FOUND);
    assertThat(provider.verifier).isNull();
  }

  @Test
  public void providersWithoutPkceGetNoChallenge() throws Exception {
    stubSuccessfulLogin();
    provider = new FakeProvider(false);
    Started started = start(newSession(KEY));
    assertThat(started.params()).doesNotContainKey("code_challenge");

    boolean done =
        newSession(KEY)
            .login(
                callback(started.state(), started.cookie()),
                new FakeHttpServletResponse(),
                provider);

    assertThat(done).isTrue();
    assertThat(provider.verifier.getCodeVerifier()).isNull();
  }

  private void stubSuccessfulLogin() throws Exception {
    doReturn(webSession).when(webSessionItem).get();
    doReturn("https://gerrit.example.com/").when(canonicalWebUrl).get(any());
    doReturn(new AuthResult(ACCOUNT, extIdKeyFactory.create("gerrit", "johndoe"), false))
        .when(accountManager)
        .authenticate(any());
  }

  private OAuthSession newSession(byte[] key) {
    return new OAuthSession(
        webSessionItem,
        () -> (IdentifiedUser) null,
        accountManager,
        canonicalWebUrl,
        tokenCache,
        extIdKeyFactory,
        authRequestFactory,
        authConfig,
        () -> key);
  }

  private record Started(
      String state, String challenge, Map<String, String> params, String cookie) {}

  private Started start(OAuthSession session) throws Exception {
    FakeHttpServletRequest req =
        new FakeHttpServletRequest("gerrit.example.com", 443, "", "/login");
    req.setPathInfo("/dashboard");
    FakeHttpServletResponse res = new FakeHttpServletResponse();

    assertThat(session.login(req, res, provider)).isFalse();

    Map<String, String> params = new HashMap<>();
    for (String kv : Splitter.on('&').split(URI.create(res.getHeader("Location")).getRawQuery())) {
      List<String> p = Splitter.on('=').limit(2).splitToList(kv);
      params.put(p.get(0), URLDecoder.decode(p.get(1), UTF_8));
    }
    String cookie = null;
    for (String h : res.getHeaders("Set-Cookie")) {
      if (h.startsWith(OAuthLoginStateCodec.COOKIE + "=")) {
        cookie = h.substring(OAuthLoginStateCodec.COOKIE.length() + 1);
      }
    }
    return new Started(params.get("state"), params.get("code_challenge"), params, cookie);
  }

  private static FakeHttpServletRequest callback(String state, String cookie) {
    FakeHttpServletRequest req =
        new FakeHttpServletRequest("gerrit.example.com", 443, "", "/oauth");
    req.setPathInfo("");
    req.setQueryString("code=the-code&state=" + URLEncoder.encode(state, UTF_8));
    if (cookie != null) {
      req.addHeader("Cookie", OAuthLoginStateCodec.COOKIE + "=" + cookie);
    }
    return req;
  }

  private static String challenge(String verifier) throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(US_ASCII));
    return BaseEncoding.base64Url().omitPadding().encode(digest);
  }

  private static class FakeProvider implements OAuthServiceProvider {
    private final boolean pkce;
    OAuthVerifier verifier;

    FakeProvider(boolean pkce) {
      this.pkce = pkce;
    }

    @Override
    public String getAuthorizationUrl() {
      return "https://idp.example.com/auth?client_id=gerrit";
    }

    @Override
    public boolean usesPkce() {
      return pkce;
    }

    @Override
    public OAuthToken getAccessToken(OAuthVerifier v) {
      verifier = v;
      return new OAuthToken("access", "Bearer", "{}");
    }

    @Override
    public OAuthUserInfo getUserInfo(OAuthToken token) {
      return new OAuthUserInfo("gerrit:johndoe", "johndoe", "j@example.com", "John Doe", null);
    }

    @Override
    public String getVersion() {
      return "2.0";
    }

    @Override
    public String getName() {
      return "Fake";
    }
  }
}
