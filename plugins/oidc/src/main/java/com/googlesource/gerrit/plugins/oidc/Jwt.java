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

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.CharMatcher;
import com.google.common.base.Splitter;
import com.google.gerrit.common.Nullable;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;
import java.util.List;

/** A signed JSON Web Token in compact form, parsed but not yet verified. */
final class Jwt {
  private static final CharMatcher BASE64URL =
      CharMatcher.inRange('A', 'Z')
          .or(CharMatcher.inRange('a', 'z'))
          .or(CharMatcher.inRange('0', '9'))
          .or(CharMatcher.anyOf("-_"));

  /** The signature algorithms accepted from the provider. HMAC and {@code none} never are. */
  enum Algorithm {
    RS256("SHA256withRSA", null, 0),
    RS384("SHA384withRSA", null, 0),
    RS512("SHA512withRSA", null, 0),
    PS256("RSASSA-PSS", MGF1ParameterSpec.SHA256, 32),
    PS384("RSASSA-PSS", MGF1ParameterSpec.SHA384, 48),
    PS512("RSASSA-PSS", MGF1ParameterSpec.SHA512, 64),
    ES256("SHA256withECDSAinP1363Format", null, 64),
    ES384("SHA384withECDSAinP1363Format", null, 96),
    ES512("SHA512withECDSAinP1363Format", null, 132);

    private final String jca;
    @Nullable private final MGF1ParameterSpec pss;
    private final int size;

    Algorithm(String jca, @Nullable MGF1ParameterSpec pss, int size) {
      this.jca = jca;
      this.pss = pss;
      this.size = size;
    }

    @Nullable
    static Algorithm named(@Nullable String name) {
      for (Algorithm a : values()) {
        if (a.name().equals(name)) {
          return a;
        }
      }
      return null;
    }

    boolean isEc() {
      return name().startsWith("ES");
    }

    /** Whether {@code key} is of the type this algorithm signs with. */
    boolean accepts(PublicKey key) {
      if (isEc()) {
        return key instanceof ECPublicKey ec
            && (ec.getParams().getCurve().getField().getFieldSize() + 7) / 8 * 2 == size;
      }
      return key instanceof RSAPublicKey rsa && rsa.getModulus().bitLength() >= 2048;
    }

    boolean verify(PublicKey key, byte[] data, byte[] signature) {
      if (!accepts(key) || (isEc() && signature.length != size)) {
        return false;
      }
      try {
        Signature s = Signature.getInstance(jca);
        if (pss != null) {
          s.setParameter(new PSSParameterSpec(pss.getDigestAlgorithm(), "MGF1", pss, size, 1));
        }
        s.initVerify(key);
        s.update(data);
        return s.verify(signature);
      } catch (GeneralSecurityException e) {
        return false;
      }
    }
  }

  /** Thrown when a token is malformed, has a bad signature, or carries the wrong claims. */
  static class InvalidTokenException extends Exception {
    private static final long serialVersionUID = 1L;

    InvalidTokenException(String message) {
      super(message);
    }
  }

  private final JsonObject header;
  private final JsonObject claims;
  private final byte[] signingInput;
  private final byte[] signature;

  private Jwt(JsonObject header, JsonObject claims, byte[] signingInput, byte[] signature) {
    this.header = header;
    this.claims = claims;
    this.signingInput = signingInput;
    this.signature = signature;
  }

  /**
   * Whether {@code s} has the shape of a compact JWS: three base64url segments, the first a JSON
   * object. Passwords and Gerrit tokens never do.
   */
  static boolean looksLikeJwt(@Nullable String s) {
    if (s == null || !s.startsWith("eyJ")) {
      return false;
    }
    List<String> parts = Splitter.on('.').splitToList(s);
    return parts.size() == 3
        && parts.stream().allMatch(p -> !p.isEmpty() && BASE64URL.matchesAllOf(p));
  }

  static Jwt parse(String s) throws InvalidTokenException {
    if (!looksLikeJwt(s)) {
      throw new InvalidTokenException("not a compact JWS");
    }
    List<String> parts = Splitter.on('.').splitToList(s);
    try {
      Base64.Decoder d = Base64.getUrlDecoder();
      return new Jwt(
          object(d.decode(parts.get(0))),
          object(d.decode(parts.get(1))),
          (parts.get(0) + "." + parts.get(1)).getBytes(US_ASCII),
          d.decode(parts.get(2)));
    } catch (IllegalArgumentException | JsonParseException | IllegalStateException e) {
      throw new InvalidTokenException("malformed token");
    }
  }

  private static JsonObject object(byte[] json) {
    return JsonParser.parseString(new String(json, UTF_8)).getAsJsonObject();
  }

  @Nullable
  Algorithm algorithm() {
    return Algorithm.named(string(header, "alg"));
  }

  @Nullable
  String keyId() {
    return string(header, "kid");
  }

  JsonObject claims() {
    return claims;
  }

  boolean verify(Algorithm alg, PublicKey key) {
    return alg.verify(key, signingInput, signature);
  }

  /** A string member of {@code o}, or null when it is absent or not a string. */
  @Nullable
  static String string(JsonObject o, String name) {
    JsonElement e = o.get(name);
    return e != null && e.isJsonPrimitive() && e.getAsJsonPrimitive().isString()
        ? e.getAsString()
        : null;
  }
}
