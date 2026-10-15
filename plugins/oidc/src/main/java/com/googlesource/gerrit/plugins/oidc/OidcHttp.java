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

import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.inject.ImplementedBy;
import com.google.inject.Singleton;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

/** The requests the plugin makes to the provider; replaced in tests. */
@ImplementedBy(OidcHttp.Jdk.class)
interface OidcHttp {
  /** GETs a JSON document. */
  JsonObject get(URI uri) throws IOException;

  /**
   * POSTs a form, authenticated as {@code clientId} with {@code client_secret_basic}, and returns
   * the JSON response.
   */
  JsonObject postForm(URI uri, Map<String, String> form, String clientId, String clientSecret)
      throws IOException;

  @Singleton
  class Jdk implements OidcHttp {
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final HttpClient client =
        HttpClient.newBuilder()
            .connectTimeout(TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    @Override
    public JsonObject get(URI uri) throws IOException {
      return send(
          HttpRequest.newBuilder(uri)
              .timeout(TIMEOUT)
              .header("Accept", "application/json")
              .build());
    }

    @Override
    public JsonObject postForm(
        URI uri, Map<String, String> form, String clientId, String clientSecret)
        throws IOException {
      // RFC 6749 section 2.3.1: both halves are form-encoded before the Basic encoding.
      String credentials = encode(clientId) + ":" + encode(clientSecret);
      String body =
          form.entrySet().stream()
              .map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
              .collect(Collectors.joining("&"));
      return send(
          HttpRequest.newBuilder(uri)
              .timeout(TIMEOUT)
              .header("Accept", "application/json")
              .header("Content-Type", "application/x-www-form-urlencoded")
              .header(
                  "Authorization",
                  "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(UTF_8)))
              .POST(HttpRequest.BodyPublishers.ofString(body))
              .build());
    }

    private JsonObject send(HttpRequest req) throws IOException {
      HttpResponse<String> rsp;
      try {
        rsp = client.send(req, HttpResponse.BodyHandlers.ofString(UTF_8));
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new IOException("Interrupted while calling " + req.uri(), e);
      }
      if (rsp.statusCode() != 200) {
        throw new IOException(
            String.format("%s %s returned %d", req.method(), req.uri(), rsp.statusCode()));
      }
      try {
        return JsonParser.parseString(rsp.body()).getAsJsonObject();
      } catch (JsonParseException | IllegalStateException e) {
        throw new IOException(req.uri() + " did not return a JSON object", e);
      }
    }

    private static String encode(String s) {
      return URLEncoder.encode(s, UTF_8);
    }
  }
}
