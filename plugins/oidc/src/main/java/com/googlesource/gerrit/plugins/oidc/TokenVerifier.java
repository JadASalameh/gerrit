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

import com.google.gerrit.common.Nullable;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.googlesource.gerrit.plugins.oidc.Jwt.InvalidTokenException;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.function.Supplier;

/** Verifies the signature and claims of tokens the provider issued. */
@Singleton
class TokenVerifier {
  private final Providers providers;
  private final Duration clockSkew;
  private final Supplier<Instant> clock;

  @Inject
  TokenVerifier(Providers providers, OidcConfig cfg) {
    this(providers, cfg.clockSkew(), Instant::now);
  }

  TokenVerifier(Providers providers, Duration clockSkew, Supplier<Instant> clock) {
    this.providers = providers;
    this.clockSkew = clockSkew;
    this.clock = clock;
  }

  /**
   * Returns the claims of {@code token} once its signature checks against a key of its issuer, the
   * issuer is one of {@code issuers}, its audience includes {@code audience} and it is within its
   * validity period.
   *
   * @throws InvalidTokenException if the token cannot be trusted
   * @throws IOException if the issuer's keys cannot be fetched
   */
  JsonObject verify(String token, Set<String> issuers, String audience)
      throws InvalidTokenException, IOException {
    Jwt jwt = Jwt.parse(token);
    Jwt.Algorithm alg = jwt.algorithm();
    if (alg == null) {
      throw new InvalidTokenException("unsupported signature algorithm");
    }
    JsonObject claims = jwt.claims();
    // Checked before fetching anything: the issuer decides where the keys come from.
    String iss = Jwt.string(claims, "iss");
    if (iss == null || !issuers.contains(iss)) {
      throw new InvalidTokenException("issuer " + iss + " is not accepted");
    }
    if (providers.keys(iss, jwt.keyId(), alg).stream().noneMatch(k -> jwt.verify(alg, k.key()))) {
      throw new InvalidTokenException("signature does not verify with the keys of " + iss);
    }
    checkValidity(claims);
    if (!hasAudience(claims, audience)) {
      throw new InvalidTokenException("token is not meant for " + audience);
    }
    return claims;
  }

  private void checkValidity(JsonObject claims) throws InvalidTokenException {
    Instant now = clock.get();
    Long exp = seconds(claims, "exp");
    if (exp == null) {
      throw new InvalidTokenException("token has no expiry");
    }
    if (!now.isBefore(Instant.ofEpochSecond(exp).plus(clockSkew))) {
      throw new InvalidTokenException("token expired");
    }
    Long nbf = seconds(claims, "nbf");
    if (nbf != null && now.isBefore(Instant.ofEpochSecond(nbf).minus(clockSkew))) {
      throw new InvalidTokenException("token is not valid yet");
    }
  }

  private static boolean hasAudience(JsonObject claims, String audience) {
    JsonElement aud = claims.get("aud");
    if (aud == null) {
      return false;
    }
    if (aud.isJsonArray()) {
      for (JsonElement a : aud.getAsJsonArray()) {
        if (a.isJsonPrimitive() && audience.equals(a.getAsString())) {
          return true;
        }
      }
      return false;
    }
    return aud.isJsonPrimitive() && audience.equals(aud.getAsString());
  }

  @Nullable
  private static Long seconds(JsonObject claims, String name) throws InvalidTokenException {
    JsonElement e = claims.get(name);
    if (e == null || e.isJsonNull()) {
      return null;
    }
    if (!e.isJsonPrimitive() || !e.getAsJsonPrimitive().isNumber()) {
      throw new InvalidTokenException(name + " is not a number");
    }
    return e.getAsLong();
  }
}
