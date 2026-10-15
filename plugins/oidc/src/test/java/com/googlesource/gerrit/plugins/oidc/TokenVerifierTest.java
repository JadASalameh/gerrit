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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.common.collect.ImmutableSet;
import com.googlesource.gerrit.plugins.oidc.FakeProvider.SigningKey;
import com.googlesource.gerrit.plugins.oidc.Jwt.InvalidTokenException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Before;
import org.junit.Test;

public class TokenVerifierTest {
  private static final Instant NOW = Instant.ofEpochSecond(1_800_000_000L);
  private static final ImmutableSet<String> BOTH = ImmutableSet.of(ISSUER, OTHER_ISSUER);

  private FakeProvider idp;
  private AtomicReference<Instant> now;
  private TokenVerifier verifier;

  @Before
  public void setUp() throws Exception {
    idp = new FakeProvider();
    now = new AtomicReference<>(NOW);
    verifier = new TokenVerifier(new Providers(idp, now::get), Duration.ofSeconds(60), now::get);
  }

  @Test
  public void acceptsRsaSignedToken() throws Exception {
    String token = FakeProvider.sign(idp.key(ISSUER), claims(ISSUER, "\"gerrit\"", 300));

    assertThat(Jwt.string(verifier.verify(token, BOTH, "gerrit"), "preferred_username"))
        .isEqualTo("jdoe");
  }

  @Test
  public void acceptsEcSignedTokenFromAnotherAcceptedIssuer() throws Exception {
    String token =
        FakeProvider.sign(idp.key(OTHER_ISSUER), claims(OTHER_ISSUER, "\"gerrit\"", 300));

    assertThat(verifier.verify(token, BOTH, "gerrit")).isNotNull();
  }

  @Test
  public void acceptsAudienceList() throws Exception {
    String token =
        FakeProvider.sign(idp.key(ISSUER), claims(ISSUER, "[\"account\", \"gerrit\"]", 300));

    assertThat(verifier.verify(token, BOTH, "gerrit")).isNotNull();
  }

  @Test
  public void rejectsOtherAudience() throws Exception {
    String token =
        FakeProvider.sign(idp.key(ISSUER), claims(ISSUER, "[\"account\", \"other\"]", 300));

    assertRejected(token, "not meant for gerrit");
  }

  @Test
  public void rejectsTokenWithoutAudience() throws Exception {
    String token =
        FakeProvider.sign(
            idp.key(ISSUER),
            "{\"iss\": \"" + ISSUER + "\", \"exp\": " + (NOW.getEpochSecond() + 300) + "}");

    assertRejected(token, "not meant for gerrit");
  }

  @Test
  public void rejectsIssuerNotAcceptedWithoutFetchingFromIt() throws Exception {
    String token =
        FakeProvider.sign(idp.key(OTHER_ISSUER), claims(OTHER_ISSUER, "\"gerrit\"", 300));

    InvalidTokenException e =
        assertThrows(
            InvalidTokenException.class,
            () -> verifier.verify(token, ImmutableSet.of(ISSUER), "gerrit"));
    assertThat(e).hasMessageThat().contains("not accepted");
    assertThat(idp.fetched).isEmpty();
  }

  @Test
  public void rejectsTokenSignedByAnotherIssuersKey() throws Exception {
    String token = FakeProvider.sign(idp.key(OTHER_ISSUER), claims(ISSUER, "\"gerrit\"", 300));

    assertRejected(token, "signature");
  }

  @Test
  public void rejectsTamperedClaims() throws Exception {
    String token = FakeProvider.sign(idp.key(ISSUER), claims(ISSUER, "\"gerrit\"", 300));
    String[] parts = token.split("\\.");
    String forged =
        parts[0]
            + "."
            + FakeProvider.b64(
                claims(ISSUER, "\"gerrit\"", 300).replace("jdoe", "admin").getBytes(UTF_8))
            + "."
            + parts[2];

    assertRejected(forged, "signature");
  }

  @Test
  public void rejectsHmacAndUnsignedTokens() throws Exception {
    String claims = FakeProvider.b64(claims(ISSUER, "\"gerrit\"", 300).getBytes(UTF_8));
    String none = FakeProvider.b64("{\"alg\":\"none\"}".getBytes(UTF_8)) + "." + claims + ".AA";
    assertRejected(none, "algorithm");

    String input = FakeProvider.b64("{\"alg\":\"HS256\"}".getBytes(UTF_8)) + "." + claims;
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec("secret".getBytes(UTF_8), "HmacSHA256"));
    assertRejected(input + "." + FakeProvider.b64(mac.doFinal(input.getBytes(UTF_8))), "algorithm");
  }

  @Test
  public void rejectsWeakRsaKeys() throws Exception {
    SigningKey weak = FakeProvider.rsa("weak", 1024);
    idp.rotate(ISSUER, weak);

    assertRejected(FakeProvider.sign(weak, claims(ISSUER, "\"gerrit\"", 300)), "signature");
  }

  @Test
  public void expiryAllowsTheClockSkew() throws Exception {
    String token = FakeProvider.sign(idp.key(ISSUER), claims(ISSUER, "\"gerrit\"", -30));
    assertThat(verifier.verify(token, BOTH, "gerrit")).isNotNull();

    String expired = FakeProvider.sign(idp.key(ISSUER), claims(ISSUER, "\"gerrit\"", -61));
    assertRejected(expired, "expired");
  }

  @Test
  public void rejectsTokenWithoutExpiry() throws Exception {
    String token =
        FakeProvider.sign(idp.key(ISSUER), "{\"iss\": \"" + ISSUER + "\", \"aud\": \"gerrit\"}");

    assertRejected(token, "no expiry");
  }

  @Test
  public void rejectsTokenNotValidYet() throws Exception {
    String token =
        FakeProvider.sign(
            idp.key(ISSUER),
            "{\"iss\": \""
                + ISSUER
                + "\", \"aud\": \"gerrit\", \"exp\": "
                + (NOW.getEpochSecond() + 600)
                + ", \"nbf\": "
                + (NOW.getEpochSecond() + 120)
                + "}");

    assertRejected(token, "not valid yet");
  }

  @Test
  public void fetchesKeysAgainForAnUnknownKeyId() throws Exception {
    verifier.verify(
        FakeProvider.sign(idp.key(ISSUER), claims(ISSUER, "\"gerrit\"", 3600)), BOTH, "gerrit");
    SigningKey rotated = FakeProvider.rsa("rsa-2");
    idp.rotate(ISSUER, rotated);
    String token = FakeProvider.sign(rotated, claims(ISSUER, "\"gerrit\"", 3600));

    // Right after a fetch the keys are not fetched again, however many unknown tokens come in.
    assertRejected(token, "signature");
    assertThat(idp.fetches("/certs")).isEqualTo(1);

    now.set(NOW.plus(Providers.MIN_REFRESH).plusSeconds(1));
    assertThat(verifier.verify(token, BOTH, "gerrit")).isNotNull();
    assertThat(idp.fetches("/certs")).isEqualTo(2);
    assertThat(idp.fetches("/openid-configuration")).isEqualTo(1);
  }

  @Test
  public void stopsTrustingRetiredKeys() throws Exception {
    SigningKey old = idp.key(ISSUER);
    verifier.verify(FakeProvider.sign(old, claims(ISSUER, "\"gerrit\"", 7200)), BOTH, "gerrit");
    idp.rotate(ISSUER, FakeProvider.rsa("rsa-2"));

    now.set(NOW.plus(Providers.MAX_AGE).plusSeconds(1));

    assertRejected(FakeProvider.sign(old, claims(ISSUER, "\"gerrit\"", 7200)), "signature");
  }

  @Test
  public void recognizesTokens() throws Exception {
    assertThat(Jwt.looksLikeJwt(FakeProvider.sign(idp.key(ISSUER), "{}"))).isTrue();
    assertThat(Jwt.looksLikeJwt("hunter2")).isFalse();
    assertThat(Jwt.looksLikeJwt("eyJ.with spaces.x")).isFalse();
    assertThat(Jwt.looksLikeJwt("eyJhbGciOi..x")).isFalse();
    assertThat(Jwt.looksLikeJwt("Zm9vYmFyYmF6cXV4")).isFalse();
    assertThat(Jwt.looksLikeJwt(null)).isFalse();
  }

  private String claims(String issuer, String aud, long expiresIn) {
    return "{\"iss\": \""
        + issuer
        + "\", \"aud\": "
        + aud
        + ", \"exp\": "
        + (now.get().getEpochSecond() + expiresIn)
        + ", \"preferred_username\": \"jdoe\"}";
  }

  private void assertRejected(String token, String reason) {
    InvalidTokenException e =
        assertThrows(InvalidTokenException.class, () -> verifier.verify(token, BOTH, "gerrit"));
    assertThat(e).hasMessageThat().contains(reason);
  }
}
