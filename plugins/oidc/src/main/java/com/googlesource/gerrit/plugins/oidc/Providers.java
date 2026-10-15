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

import com.google.common.base.CharMatcher;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.FluentLogger;
import com.google.gerrit.common.Nullable;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * The discovery document and signing keys of each issuer, fetched on first use. Keys are fetched
 * again when a token names one we do not have, at most every {@link #MIN_REFRESH}, and when they
 * are older than {@link #MAX_AGE}, so a key the provider retires stops being trusted.
 */
@Singleton
class Providers {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  static final Duration MIN_REFRESH = Duration.ofSeconds(30);
  static final Duration MAX_AGE = Duration.ofHours(1);

  /** The endpoints of a provider, from its discovery document. */
  record Metadata(String issuer, URI authorizationEndpoint, URI tokenEndpoint, URI jwksUri) {}

  /** A key from a JWKS, with its {@code kid} and {@code alg} when the provider gave them. */
  record Key(@Nullable String id, @Nullable String alg, PublicKey key) {}

  private record Keys(ImmutableList<Key> keys, Instant fetchedAt) {}

  private final OidcHttp http;
  private final Supplier<Instant> clock;
  private final Map<String, Metadata> metadata = new ConcurrentHashMap<>();
  private final Map<String, Keys> keys = new ConcurrentHashMap<>();

  @Inject
  Providers(OidcHttp http) {
    this(http, Instant::now);
  }

  Providers(OidcHttp http, Supplier<Instant> clock) {
    this.http = http;
    this.clock = clock;
  }

  /** The discovery document of {@code issuer}, which must name that same issuer. */
  Metadata metadata(String issuer) throws IOException {
    Metadata m = metadata.get(issuer);
    if (m != null) {
      return m;
    }
    URI uri =
        URI.create(
            CharMatcher.is('/').trimTrailingFrom(issuer) + "/.well-known/openid-configuration");
    JsonObject doc = http.get(uri);
    if (!issuer.equals(Jwt.string(doc, "issuer"))) {
      throw new IOException(String.format("%s names issuer %s", uri, Jwt.string(doc, "issuer")));
    }
    m =
        new Metadata(
            issuer,
            endpoint(doc, "authorization_endpoint"),
            endpoint(doc, "token_endpoint"),
            endpoint(doc, "jwks_uri"));
    metadata.put(issuer, m);
    return m;
  }

  /**
   * The keys of {@code issuer} that may have signed a token naming {@code kid} with {@code alg}.
   * The caller checked that the issuer is one we accept: this fetches from it.
   */
  ImmutableList<Key> keys(String issuer, @Nullable String kid, Jwt.Algorithm alg)
      throws IOException {
    Keys k = current(issuer, false);
    ImmutableList<Key> found = matching(k, kid, alg);
    if (found.isEmpty() && k.fetchedAt().plus(MIN_REFRESH).isBefore(clock.get())) {
      found = matching(current(issuer, true), kid, alg);
    }
    return found;
  }

  private synchronized Keys current(String issuer, boolean refresh) throws IOException {
    Keys k = keys.get(issuer);
    Instant now = clock.get();
    if (k != null && !refresh && k.fetchedAt().plus(MAX_AGE).isAfter(now)) {
      return k;
    }
    if (k != null && refresh && k.fetchedAt().plus(MIN_REFRESH).isAfter(now)) {
      return k;
    }
    k = new Keys(parse(http.get(metadata(issuer).jwksUri())), now);
    keys.put(issuer, k);
    return k;
  }

  private static ImmutableList<Key> matching(Keys k, @Nullable String kid, Jwt.Algorithm alg) {
    return k.keys().stream()
        .filter(key -> kid == null || kid.equals(key.id()))
        .filter(key -> key.alg() == null || key.alg().equals(alg.name()))
        .filter(key -> alg.accepts(key.key()))
        .collect(ImmutableList.toImmutableList());
  }

  /** The signing keys of a JWKS; keys of unknown types, or meant for encryption, are skipped. */
  static ImmutableList<Key> parse(JsonObject jwks) {
    ImmutableList.Builder<Key> b = ImmutableList.builder();
    JsonElement list = jwks.get("keys");
    if (list == null || !list.isJsonArray()) {
      return b.build();
    }
    for (JsonElement e : list.getAsJsonArray()) {
      if (!e.isJsonObject()) {
        continue;
      }
      JsonObject jwk = e.getAsJsonObject();
      String use = Jwt.string(jwk, "use");
      if (use != null && !use.equals("sig")) {
        continue;
      }
      try {
        PublicKey key = publicKey(jwk);
        if (key != null) {
          b.add(new Key(Jwt.string(jwk, "kid"), Jwt.string(jwk, "alg"), key));
        }
      } catch (GeneralSecurityException | IllegalArgumentException | NullPointerException ex) {
        logger.atWarning().log("Skipping unreadable key %s", Jwt.string(jwk, "kid"));
      }
    }
    return b.build();
  }

  @Nullable
  private static PublicKey publicKey(JsonObject jwk) throws GeneralSecurityException {
    String kty = Objects.requireNonNullElse(Jwt.string(jwk, "kty"), "");
    switch (kty) {
      case "RSA" -> {
        return KeyFactory.getInstance("RSA")
            .generatePublic(new RSAPublicKeySpec(number(jwk, "n"), number(jwk, "e")));
      }
      case "EC" -> {
        String curve =
            switch (Objects.requireNonNullElse(Jwt.string(jwk, "crv"), "")) {
              case "P-256" -> "secp256r1";
              case "P-384" -> "secp384r1";
              case "P-521" -> "secp521r1";
              default -> null;
            };
        if (curve == null) {
          return null;
        }
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(curve));
        return KeyFactory.getInstance("EC")
            .generatePublic(
                new ECPublicKeySpec(
                    new ECPoint(number(jwk, "x"), number(jwk, "y")),
                    params.getParameterSpec(ECParameterSpec.class)));
      }
      default -> {
        return null;
      }
    }
  }

  private static BigInteger number(JsonObject jwk, String name) {
    return new BigInteger(1, Base64.getUrlDecoder().decode(Jwt.string(jwk, name)));
  }

  private static URI endpoint(JsonObject doc, String name) throws IOException {
    String v = Jwt.string(doc, name);
    if (v == null) {
      throw new IOException("Discovery document has no " + name);
    }
    try {
      return URI.create(v);
    } catch (IllegalArgumentException e) {
      throw new IOException("Discovery document has an invalid " + name, e);
    }
  }
}
