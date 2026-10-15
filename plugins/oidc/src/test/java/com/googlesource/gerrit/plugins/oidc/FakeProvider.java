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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** An OpenID provider in memory: discovery, keys and the token endpoint. */
class FakeProvider implements OidcHttp {
  static final String ISSUER = "https://idp.example.com/realms/test";
  static final String OTHER_ISSUER = "https://idp2.example.com/realms/test";

  record SigningKey(String kid, String alg, KeyPair pair) {}

  private final Map<String, List<SigningKey>> keys = new HashMap<>();
  final List<URI> fetched = new ArrayList<>();
  Map<String, String> lastForm;
  String lastClientId;
  String lastClientSecret;
  JsonObject tokenResponse = new JsonObject();

  FakeProvider() throws GeneralSecurityException {
    keys.put(ISSUER, new ArrayList<>(List.of(rsa("rsa-1"))));
    keys.put(OTHER_ISSUER, new ArrayList<>(List.of(ec("ec-1"))));
  }

  static SigningKey rsa(String kid) throws GeneralSecurityException {
    return rsa(kid, 2048);
  }

  static SigningKey rsa(String kid, int bits) throws GeneralSecurityException {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(bits);
    return new SigningKey(kid, "RS256", g.generateKeyPair());
  }

  static SigningKey ec(String kid) throws GeneralSecurityException {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec("secp256r1"));
    return new SigningKey(kid, "ES256", g.generateKeyPair());
  }

  SigningKey key(String issuer) {
    return keys.get(issuer).get(0);
  }

  void rotate(String issuer, SigningKey key) {
    keys.put(issuer, new ArrayList<>(List.of(key)));
  }

  @Override
  public JsonObject get(URI uri) throws IOException {
    fetched.add(uri);
    for (String issuer : keys.keySet()) {
      if (uri.toString().equals(issuer + "/.well-known/openid-configuration")) {
        JsonObject doc = new JsonObject();
        doc.addProperty("issuer", issuer);
        doc.addProperty("authorization_endpoint", issuer + "/protocol/openid-connect/auth");
        doc.addProperty("token_endpoint", issuer + "/protocol/openid-connect/token");
        doc.addProperty("jwks_uri", issuer + "/protocol/openid-connect/certs");
        return doc;
      }
      if (uri.toString().equals(issuer + "/protocol/openid-connect/certs")) {
        JsonArray list = new JsonArray();
        for (SigningKey k : keys.get(issuer)) {
          list.add(jwk(k));
        }
        JsonObject jwks = new JsonObject();
        jwks.add("keys", list);
        return jwks;
      }
    }
    throw new IOException("GET " + uri + " returned 404");
  }

  @Override
  public JsonObject postForm(
      URI uri, Map<String, String> form, String clientId, String clientSecret) {
    lastForm = form;
    lastClientId = clientId;
    lastClientSecret = clientSecret;
    return tokenResponse;
  }

  int fetches(String suffix) {
    return (int) fetched.stream().filter(u -> u.toString().endsWith(suffix)).count();
  }

  private static JsonObject jwk(SigningKey k) {
    JsonObject jwk = new JsonObject();
    jwk.addProperty("kid", k.kid());
    jwk.addProperty("use", "sig");
    jwk.addProperty("alg", k.alg());
    if (k.pair().getPublic() instanceof RSAPublicKey rsa) {
      jwk.addProperty("kty", "RSA");
      jwk.addProperty("n", b64(rsa.getModulus()));
      jwk.addProperty("e", b64(rsa.getPublicExponent()));
    } else {
      ECPublicKey ec = (ECPublicKey) k.pair().getPublic();
      jwk.addProperty("kty", "EC");
      jwk.addProperty("crv", "P-256");
      jwk.addProperty("x", b64(ec.getW().getAffineX(), 32));
      jwk.addProperty("y", b64(ec.getW().getAffineY(), 32));
    }
    return jwk;
  }

  /** A token signed by {@code key}, with {@code claims} as JSON. */
  static String sign(SigningKey key, String claims) throws GeneralSecurityException {
    return sign(key.alg(), key.kid(), key.pair().getPrivate(), claims);
  }

  static String sign(String alg, String kid, PrivateKey key, String claims)
      throws GeneralSecurityException {
    JsonObject header = new JsonObject();
    header.addProperty("alg", alg);
    header.addProperty("typ", "JWT");
    header.addProperty("kid", kid);
    String input =
        b64(header.toString().getBytes(UTF_8))
            + "."
            + b64(JsonParser.parseString(claims).toString().getBytes(UTF_8));
    Signature s =
        Signature.getInstance(
            alg.startsWith("ES") ? "SHA256withECDSAinP1363Format" : "SHA256withRSA");
    s.initSign(key);
    s.update(input.getBytes(UTF_8));
    return input + "." + b64(s.sign());
  }

  static String b64(byte[] b) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  private static String b64(BigInteger n) {
    byte[] b = n.toByteArray();
    if (b[0] == 0 && b.length > 1) {
      byte[] t = new byte[b.length - 1];
      System.arraycopy(b, 1, t, 0, t.length);
      b = t;
    }
    return b64(b);
  }

  private static String b64(BigInteger n, int size) {
    byte[] b = n.toByteArray();
    byte[] out = new byte[size];
    int len = Math.min(b.length, size);
    System.arraycopy(b, b.length - len, out, size - len, len);
    return b64(out);
  }
}
