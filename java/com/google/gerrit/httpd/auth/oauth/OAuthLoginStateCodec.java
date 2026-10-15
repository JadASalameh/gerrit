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

import static com.google.gerrit.server.ioutil.BasicSerialization.readFixInt64;
import static com.google.gerrit.server.ioutil.BasicSerialization.readString;
import static com.google.gerrit.server.ioutil.BasicSerialization.readVarInt32;
import static com.google.gerrit.server.ioutil.BasicSerialization.writeFixInt64;
import static com.google.gerrit.server.ioutil.BasicSerialization.writeString;
import static com.google.gerrit.server.ioutil.BasicSerialization.writeVarInt32;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Strings;
import com.google.gerrit.common.Nullable;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Turns the part of an OAuth login that must survive the round trip to the provider into a
 * self-contained cookie value and back.
 *
 * <p>Between the redirect to the provider and its callback, Gerrit needs the {@code state} it sent,
 * the page to return to, the PKCE code verifier and whether the login links an identity to the
 * current account. Kept in the servlet session they tie the callback to the node that started the
 * login; carried in this cookie, signed with the web-session signing key, any node holding the key
 * can finish it.
 *
 * <p>The value is the serialized state followed by an HMAC-SHA256, base64url encoded. The MAC also
 * covers a purpose label, so a login-state value can never pass for a session cookie signed with
 * the same key, or the reverse.
 */
final class OAuthLoginStateCodec {
  /** Name of the cookie that carries the login state. */
  static final String COOKIE = "GerritOAuthLogin";

  private static final int VERSION = 1;
  private static final String MAC_ALGORITHM = "HmacSHA256";
  private static final int MAC_LENGTH = 32;
  private static final byte[] PURPOSE = "gerrit-oauth-login-state\0".getBytes(UTF_8);

  /** What the callback needs from the request that started the login. */
  record State(
      String state,
      @Nullable String redirectToken,
      @Nullable String codeVerifier,
      boolean linkMode,
      long expiresAtMillis) {}

  private final byte[] key;

  OAuthLoginStateCodec(byte[] key) {
    if (key == null || key.length < 16) {
      throw new IllegalArgumentException("web session signing key must be at least 16 bytes");
    }
    this.key = key.clone();
  }

  String encode(State s) {
    ByteArrayOutputStream buf = new ByteArrayOutputStream(160);
    try {
      writeVarInt32(buf, VERSION);
      writeFixInt64(buf, s.expiresAtMillis());
      writeString(buf, s.state());
      writeString(buf, s.redirectToken());
      writeString(buf, s.codeVerifier());
      writeVarInt32(buf, s.linkMode() ? 1 : 0);
    } catch (IOException impossible) {
      throw new IllegalStateException(impossible);
    }
    byte[] payload = buf.toByteArray();
    byte[] mac = mac(payload);
    byte[] token = Arrays.copyOf(payload, payload.length + mac.length);
    System.arraycopy(mac, 0, token, payload.length, mac.length);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
  }

  /**
   * Returns the login state the value carries, or null when it was not issued with this key, is
   * malformed, or expired before {@code nowMillis}.
   */
  @Nullable
  State decode(String token, long nowMillis) {
    if (Strings.isNullOrEmpty(token)) {
      return null;
    }
    byte[] bytes;
    try {
      bytes = Base64.getUrlDecoder().decode(token);
    } catch (IllegalArgumentException notBase64) {
      return null;
    }
    if (bytes.length <= MAC_LENGTH) {
      return null;
    }
    byte[] payload = Arrays.copyOf(bytes, bytes.length - MAC_LENGTH);
    byte[] mac = Arrays.copyOfRange(bytes, bytes.length - MAC_LENGTH, bytes.length);
    if (!MessageDigest.isEqual(mac(payload), mac)) {
      return null;
    }
    try (ByteArrayInputStream in = new ByteArrayInputStream(payload)) {
      if (readVarInt32(in) != VERSION) {
        return null;
      }
      long expiresAt = readFixInt64(in);
      String state = readString(in);
      String redirectToken = readString(in);
      String codeVerifier = readString(in);
      boolean linkMode = readVarInt32(in) != 0;
      if (state == null || expiresAt <= nowMillis) {
        return null;
      }
      return new State(state, redirectToken, codeVerifier, linkMode, expiresAt);
    } catch (IOException | RuntimeException malformed) {
      return null;
    }
  }

  private byte[] mac(byte[] payload) {
    try {
      Mac mac = Mac.getInstance(MAC_ALGORITHM);
      mac.init(new SecretKeySpec(key, MAC_ALGORITHM));
      mac.update(PURPOSE);
      return mac.doFinal(payload);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(MAC_ALGORITHM + " unavailable", e);
    }
  }
}
