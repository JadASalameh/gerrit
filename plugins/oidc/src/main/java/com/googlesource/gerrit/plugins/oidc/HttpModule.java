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

import com.google.gerrit.extensions.annotations.Exports;
import com.google.gerrit.extensions.auth.oauth.OAuthServiceProvider;
import com.google.inject.AbstractModule;

/** The web login, at {@code /login} once {@code auth.type} is {@code OAUTH}. */
public class HttpModule extends AbstractModule {
  @Override
  protected void configure() {
    bind(OAuthServiceProvider.class)
        .annotatedWith(Exports.named(Module.EXPORT_NAME))
        .to(OidcServiceProvider.class);
  }
}
