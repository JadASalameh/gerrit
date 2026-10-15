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
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.gerrit.httpd.auth.oauth.OAuthLoginStateCodec.State;
import java.util.Arrays;
import java.util.Base64;
import org.junit.Test;

public class OAuthLoginStateCodecTest {
  private static final byte[] KEY = "0123456789abcdef0123456789abcdef".getBytes(UTF_8);
  private static final long NOW = 1_700_000_000_000L;

  private final OAuthLoginStateCodec codec = new OAuthLoginStateCodec(KEY);

  @Test
  public void roundTrip() {
    State s = new State("st", "/login/dashboard", "verifier", true, NOW + 60_000);

    assertThat(codec.decode(codec.encode(s), NOW)).isEqualTo(s);
  }

  @Test
  public void roundTripWithoutOptionalFields() {
    State s = new State("st", null, null, false, NOW + 60_000);

    assertThat(codec.decode(codec.encode(s), NOW)).isEqualTo(s);
  }

  @Test
  public void rejectsExpiredState() {
    String token = codec.encode(new State("st", "/login", null, false, NOW));

    assertThat(codec.decode(token, NOW)).isNull();
    assertThat(codec.decode(token, NOW - 1)).isNotNull();
  }

  @Test
  public void rejectsValueSignedWithAnotherKey() {
    OAuthLoginStateCodec other =
        new OAuthLoginStateCodec("fedcba9876543210fedcba9876543210".getBytes(UTF_8));
    String token = other.encode(new State("st", "/login", null, false, NOW + 60_000));

    assertThat(codec.decode(token, NOW)).isNull();
  }

  @Test
  public void rejectsTamperedValue() {
    byte[] bytes =
        Base64.getUrlDecoder()
            .decode(codec.encode(new State("st", "/login", null, false, NOW + 60_000)));
    bytes[3] ^= 1;
    String tampered = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

    assertThat(codec.decode(tampered, NOW)).isNull();
  }

  @Test
  public void rejectsGarbage() {
    assertThat(codec.decode("", NOW)).isNull();
    assertThat(codec.decode("not base64!", NOW)).isNull();
    assertThat(codec.decode("AAAA", NOW)).isNull();
    byte[] macOnly = new byte[32];
    Arrays.fill(macOnly, (byte) 7);
    assertThat(codec.decode(Base64.getUrlEncoder().encodeToString(macOnly), NOW)).isNull();
  }

  @Test
  public void requiresALongEnoughKey() {
    assertThrows(IllegalArgumentException.class, () -> new OAuthLoginStateCodec(new byte[15]));
    assertThrows(IllegalArgumentException.class, () -> new OAuthLoginStateCodec(null));
  }
}
