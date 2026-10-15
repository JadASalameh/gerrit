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

package com.google.gerrit.auth.ldap;

import com.google.common.base.Strings;
import com.google.common.flogger.FluentLogger;
import com.google.gerrit.server.account.AccountException;
import com.google.gerrit.server.account.AuthenticationFailedException;
import com.google.gerrit.server.auth.AuthenticationUnavailableException;
import com.google.gerrit.server.auth.NoSuchUserException;
import com.google.gerrit.server.config.GerritServerConfig;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.io.IOException;
import java.util.Locale;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.security.auth.login.LoginException;
import org.eclipse.jgit.lib.Config;

/**
 * Checks a username and password against the configured {@code ldap.server}, the way {@code
 * auth.type = LDAP} does for its login form and for Git over HTTP: find the account's DN, then bind
 * as it.
 *
 * <p>For sites whose web login is another realm (an OAuth provider, say) but whose users and
 * service accounts still authenticate Git and REST calls with their directory password. Install
 * {@link LdapPasswordModule} to get it. Only the password is checked; group membership and account
 * details still come from the site's realm.
 */
@Singleton
public class LdapPasswordAuthenticator {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  private final Helper helper;
  private final boolean localUsernameToLowerCase;

  @Inject
  LdapPasswordAuthenticator(Helper helper, @GerritServerConfig Config config) {
    this.helper = helper;
    this.localUsernameToLowerCase = config.getBoolean("ldap", "localUsernameToLowerCase", false);
  }

  /**
   * Returns whether {@code password} binds as the directory account of {@code username}. An empty
   * password never matches: many directories accept it as an anonymous bind.
   *
   * @throws AuthenticationUnavailableException when the directory cannot be queried
   */
  public boolean authenticate(String username, String password)
      throws AuthenticationUnavailableException {
    if (Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(password)) {
      return false;
    }
    if (localUsernameToLowerCase) {
      username = username.toLowerCase(Locale.US);
    }
    try {
      DirContext ctx = helper.open();
      try {
        LdapQuery.Result account = helper.findAccount(helper.getSchema(ctx), ctx, username, false);
        helper.close(helper.authenticate(account.getDN(), password));
        return true;
      } finally {
        helper.close(ctx);
      }
    } catch (NoSuchUserException | AuthenticationFailedException e) {
      return false;
    } catch (AccountException e) {
      logger.atWarning().withCause(e).log("Cannot check the LDAP password of %s", username);
      return false;
    } catch (IOException | NamingException | LoginException e) {
      logger.atSevere().withCause(e).log("Cannot query LDAP to authenticate %s", username);
      throw new AuthenticationUnavailableException("Cannot query LDAP for account", e);
    }
  }
}
