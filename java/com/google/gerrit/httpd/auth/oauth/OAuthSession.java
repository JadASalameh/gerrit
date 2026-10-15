// Copyright (C) 2015 The Android Open Source Project
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

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

import com.google.common.base.CharMatcher;
import com.google.common.base.Strings;
import com.google.common.flogger.FluentLogger;
import com.google.common.io.BaseEncoding;
import com.google.gerrit.auth.oauth.OAuthTokenCache;
import com.google.gerrit.common.Nullable;
import com.google.gerrit.entities.Account;
import com.google.gerrit.extensions.auth.oauth.OAuthServiceProvider;
import com.google.gerrit.extensions.auth.oauth.OAuthToken;
import com.google.gerrit.extensions.auth.oauth.OAuthUserInfo;
import com.google.gerrit.extensions.auth.oauth.OAuthVerifier;
import com.google.gerrit.extensions.registration.DynamicItem;
import com.google.gerrit.extensions.restapi.Url;
import com.google.gerrit.httpd.CanonicalWebUrl;
import com.google.gerrit.httpd.WebSession;
import com.google.gerrit.httpd.WebSessionSigningKeyModule;
import com.google.gerrit.server.IdentifiedUser;
import com.google.gerrit.server.account.AccountException;
import com.google.gerrit.server.account.AccountManager;
import com.google.gerrit.server.account.AuthRequest;
import com.google.gerrit.server.account.AuthResult;
import com.google.gerrit.server.account.externalids.ExternalIdKeyFactory;
import com.google.gerrit.server.config.AuthConfig;
import com.google.gerrit.server.util.time.TimeUtil;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.name.Named;
import com.google.inject.servlet.SessionScoped;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Optional;
import javax.servlet.ServletRequest;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.eclipse.jgit.errors.ConfigInvalidException;

@SessionScoped
/* OAuth protocol implementation */
class OAuthSession {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  private static final SecureRandom randomState = newRandomGenerator();

  /** How long a login may take between the redirect to the provider and its callback. */
  private static final Duration LOGIN_STATE_MAX_AGE = Duration.ofMinutes(10);

  private String state;
  private final DynamicItem<WebSession> webSession;
  private final Provider<IdentifiedUser> identifiedUser;
  private final AccountManager accountManager;
  private final CanonicalWebUrl urlProvider;
  private final OAuthTokenCache tokenCache;
  private final AuthConfig authConfig;
  @Nullable private final OAuthLoginStateCodec loginStateCodec;
  private OAuthServiceProvider serviceProvider;
  private OAuthUserInfo user;
  private Account.Id accountId;
  private String redirectToken;
  @Nullable private String codeVerifier;
  private boolean linkMode;
  private final ExternalIdKeyFactory externalIdKeyFactory;
  private final AuthRequest.Factory authRequestFactory;

  @Inject
  OAuthSession(
      DynamicItem<WebSession> webSession,
      Provider<IdentifiedUser> identifiedUser,
      AccountManager accountManager,
      CanonicalWebUrl urlProvider,
      OAuthTokenCache tokenCache,
      ExternalIdKeyFactory externalIdKeyFactory,
      AuthRequest.Factory authRequestFactory,
      AuthConfig authConfig,
      @Named(WebSessionSigningKeyModule.KEY) Provider<byte[]> signingKey) {
    this.state = generateRandomState();
    this.identifiedUser = identifiedUser;
    this.webSession = webSession;
    this.accountManager = accountManager;
    this.urlProvider = urlProvider;
    this.tokenCache = tokenCache;
    this.externalIdKeyFactory = externalIdKeyFactory;
    this.authRequestFactory = authRequestFactory;
    this.authConfig = authConfig;
    // With a signing key the login state travels in a signed cookie, so the provider's callback
    // may reach any node. Without one it stays in this servlet session, as before.
    byte[] key = signingKey.get();
    this.loginStateCodec = key != null && key.length >= 16 ? new OAuthLoginStateCodec(key) : null;
  }

  boolean isLoggedIn() {
    return user != null;
  }

  boolean isOAuthFinal(HttpServletRequest request) {
    return Strings.emptyToNull(request.getParameter("code")) != null;
  }

  boolean login(
      HttpServletRequest request, HttpServletResponse response, OAuthServiceProvider oauth)
      throws IOException {
    logger.atFine().log("Login %s", this);

    if (isOAuthFinal(request)) {
      OAuthLoginStateCodec.State saved = takeLoginState(request, response);
      if (saved != null) {
        redirectToken = saved.redirectToken();
        codeVerifier = saved.codeVerifier();
        linkMode = saved.linkMode();
        if (!stateMatches(request, saved.state())) {
          response.sendError(HttpServletResponse.SC_NOT_FOUND);
          return false;
        }
      } else if (!checkState(request)) {
        response.sendError(HttpServletResponse.SC_NOT_FOUND);
        return false;
      }
      // A state answers one callback: a replay, even in this servlet session, is refused.
      state = null;

      logger.atFine().log("Login-Retrieve-User %s", this);
      OAuthToken token =
          oauth.getAccessToken(new OAuthVerifier(request.getParameter("code"), codeVerifier));
      codeVerifier = null;
      user = oauth.getUserInfo(token);

      if (isLoggedIn()) {
        logger.atFine().log("Login-SUCCESS %s", this);
        authenticateAndRedirect(request, response, token);
        return true;
      }
      response.sendError(SC_UNAUTHORIZED);
      return false;
    }
    logger.atFine().log("Login-PHASE1 %s", this);
    redirectToken = request.getRequestURI();
    // We are here in content of filter.
    // Due to this Jetty limitation:
    // https://bz.apache.org/bugzilla/show_bug.cgi?id=28323
    // we cannot use LoginUrlToken.getToken() method,
    // because it relies on getPathInfo() and it is always null here.
    redirectToken = redirectToken.substring(request.getContextPath().length());
    state = generateRandomState();
    StringBuilder url =
        new StringBuilder(oauth.getAuthorizationUrl()).append("&state=").append(state);
    if (oauth.usesPkce()) {
      codeVerifier = generateCodeVerifier();
      url.append("&code_challenge=")
          .append(codeChallenge(codeVerifier))
          .append("&code_challenge_method=S256");
    } else {
      codeVerifier = null;
    }
    saveLoginState(request, response);
    response.sendRedirect(url.toString());
    return false;
  }

  private void saveLoginState(HttpServletRequest req, HttpServletResponse rsp) {
    if (loginStateCodec == null) {
      return;
    }
    long expiresAt = TimeUtil.nowMs() + LOGIN_STATE_MAX_AGE.toMillis();
    String value =
        loginStateCodec.encode(
            new OAuthLoginStateCodec.State(
                state, redirectToken, codeVerifier, linkMode, expiresAt));
    rsp.addCookie(loginStateCookie(req, value, (int) LOGIN_STATE_MAX_AGE.toSeconds()));
  }

  /**
   * Returns the state the login-state cookie carries and erases the cookie, or null when there is
   * no valid cookie: no signing key, a login started before the key existed, or an expired or
   * forged value. The caller then falls back to this servlet session.
   */
  @Nullable
  private OAuthLoginStateCodec.State takeLoginState(
      HttpServletRequest req, HttpServletResponse rsp) {
    if (loginStateCodec == null || req.getCookies() == null) {
      return null;
    }
    for (Cookie c : req.getCookies()) {
      if (OAuthLoginStateCodec.COOKIE.equals(c.getName())) {
        rsp.addCookie(loginStateCookie(req, "", 0));
        OAuthLoginStateCodec.State s = loginStateCodec.decode(c.getValue(), TimeUtil.nowMs());
        if (s == null) {
          logger.atWarning().log("Ignoring an invalid or expired OAuth login-state cookie");
        }
        return s;
      }
    }
    return null;
  }

  private Cookie loginStateCookie(HttpServletRequest req, String value, int maxAgeSeconds) {
    String path = authConfig.getCookiePath();
    if (Strings.isNullOrEmpty(path)) {
      path = Strings.isNullOrEmpty(req.getContextPath()) ? "/" : req.getContextPath();
    }
    Cookie c = new Cookie(OAuthLoginStateCodec.COOKIE, value);
    String domain = authConfig.getCookieDomain();
    if (!Strings.isNullOrEmpty(domain)) {
      c.setDomain(domain);
    }
    c.setPath(path);
    c.setMaxAge(maxAgeSeconds);
    c.setSecure(req.isSecure() || "https".equals(req.getScheme()));
    c.setHttpOnly(true);
    return c;
  }

  private static boolean stateMatches(ServletRequest request, String expected) {
    String s = Strings.nullToEmpty(request.getParameter("state"));
    if (!MessageDigest.isEqual(s.getBytes(UTF_8), expected.getBytes(UTF_8))) {
      logger.atSevere().log("Illegal request state '%s' on OAuth login-state cookie", s);
      return false;
    }
    return true;
  }

  /** PKCE S256 challenge (RFC 7636 section 4.2): BASE64URL(SHA256(ASCII(code_verifier))). */
  private static String codeChallenge(String verifier) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(US_ASCII));
      return BaseEncoding.base64Url().omitPadding().encode(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  private void authenticateAndRedirect(
      HttpServletRequest req, HttpServletResponse rsp, OAuthToken token) throws IOException {
    AuthRequest areq = authRequestFactory.create(externalIdKeyFactory.parse(user.getExternalId()));
    AuthResult arsp;
    try {
      String claimedIdentifier = user.getClaimedIdentity();
      if (!Strings.isNullOrEmpty(claimedIdentifier)) {
        if (!authenticateWithIdentityClaimedDuringHandshake(areq, rsp, claimedIdentifier)) {
          return;
        }
      } else if (linkMode) {
        if (!authenticateWithLinkedIdentity(areq, rsp)) {
          return;
        }
      }
      areq.setUserName(user.getUserName());
      areq.setEmailAddress(user.getEmailAddress());
      areq.setDisplayName(user.getDisplayName());
      arsp = accountManager.authenticate(areq);

      accountId = arsp.getAccountId();
      tokenCache.put(accountId, token);
    } catch (AccountException e) {
      logger.atSevere().withCause(e).log("Unable to authenticate user \"%s\"", user);
      rsp.sendError(HttpServletResponse.SC_FORBIDDEN);
      return;
    }

    webSession.get().login(arsp, true);
    String loginPath = Strings.nullToEmpty(redirectToken);
    String suffix =
        loginPath.length() > OAuthWebFilter.GERRIT_LOGIN.length()
            ? loginPath.substring(OAuthWebFilter.GERRIT_LOGIN.length() + 1)
            : "";
    suffix = CharMatcher.anyOf("/").trimLeadingFrom(Url.decode(suffix));
    StringBuilder rdr = new StringBuilder(urlProvider.get(req));
    rdr.append(suffix);
    rsp.sendRedirect(rdr.toString());
  }

  private boolean authenticateWithIdentityClaimedDuringHandshake(
      AuthRequest req, HttpServletResponse rsp, String claimedIdentifier)
      throws AccountException, IOException {
    Optional<Account.Id> claimedId = accountManager.lookup(claimedIdentifier);
    Optional<Account.Id> actualId = accountManager.lookup(user.getExternalId());
    if (claimedId.isPresent() && actualId.isPresent()) {
      if (claimedId.get().equals(actualId.get())) {
        // Both link to the same account, that's what we expected.
        logger.atFine().log("OAuth2: claimed identity equals current id");
      } else {
        // This is (for now) a fatal error. There are two records
        // for what might be the same user.
        //
        logger.atSevere().log(
            "OAuth accounts disagree over user identity:\n"
                + "  Claimed ID: %s is %s\n"
                + "  Delgate ID: %s is %s",
            claimedId.get(), claimedIdentifier, actualId.get(), user.getExternalId());
        rsp.sendError(HttpServletResponse.SC_FORBIDDEN);
        return false;
      }
    } else if (claimedId.isPresent() && !actualId.isPresent()) {
      // Claimed account already exists: link to it.
      //
      logger.atInfo().log("OAuth2: linking claimed identity to %s", claimedId.get());
      try {
        accountManager.link(claimedId.get(), req);
      } catch (ConfigInvalidException e) {
        logger.atSevere().log(
            "Cannot link: %s to user identity:\n  Claimed ID: %s is %s",
            user.getExternalId(), claimedId.get(), claimedIdentifier);
        rsp.sendError(HttpServletResponse.SC_FORBIDDEN);
        return false;
      }
    }
    return true;
  }

  private boolean authenticateWithLinkedIdentity(AuthRequest areq, HttpServletResponse rsp)
      throws AccountException, IOException {
    try {
      accountManager.link(identifiedUser.get().getAccountId(), areq);
    } catch (ConfigInvalidException e) {
      logger.atSevere().log(
          "Cannot link: %s to user identity: %s",
          user.getExternalId(), identifiedUser.get().getAccountId());
      rsp.sendError(HttpServletResponse.SC_FORBIDDEN);
      return false;
    } finally {
      linkMode = false;
    }
    return true;
  }

  void logout() {
    if (accountId != null) {
      tokenCache.remove(accountId);
      accountId = null;
    }
    user = null;
    redirectToken = null;
    serviceProvider = null;
  }

  private boolean checkState(ServletRequest request) {
    String s = Strings.nullToEmpty(request.getParameter("state"));
    if (!s.equals(state)) {
      logger.atSevere().log("Illegal request state '%s' on OAuthProtocol %s", s, this);
      return false;
    }
    return true;
  }

  private static SecureRandom newRandomGenerator() {
    try {
      return SecureRandom.getInstance("SHA1PRNG");
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("No SecureRandom available for GitHub authentication", e);
    }
  }

  private static String generateRandomState() {
    byte[] state = new byte[32];
    randomState.nextBytes(state);
    return BaseEncoding.base64Url().encode(state);
  }

  /** 43 unreserved characters, as RFC 7636 section 4.1 requires (no base64 padding). */
  private static String generateCodeVerifier() {
    byte[] verifier = new byte[32];
    randomState.nextBytes(verifier);
    return BaseEncoding.base64Url().omitPadding().encode(verifier);
  }

  @Override
  public String toString() {
    return "OAuthSession [token=" + tokenCache.get(accountId) + ", user=" + user + "]";
  }

  public void setServiceProvider(OAuthServiceProvider provider) {
    this.serviceProvider = provider;
  }

  public OAuthServiceProvider getServiceProvider() {
    return serviceProvider;
  }

  public void setLinkMode(boolean linkMode) {
    this.linkMode = linkMode;
  }

  public boolean isLinkMode() {
    return linkMode;
  }
}
