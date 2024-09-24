/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.cloud.hosted.kafka.auth;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.common.collect.ImmutableSet;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;
import org.apache.kafka.common.security.oauthbearer.internals.secured.SerializedJwt;
import org.apache.kafka.common.security.oauthbearer.internals.unsecured.OAuthBearerUnsecuredJws;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit test for GcpLoginCallbackHandlerTest. */
@RunWith(JUnit4.class)
public final class GcpLoginCallbackHandlerTest {
  static class FakeGoogleCredentials extends GcpLoginCallbackHandler.StubGoogleCredentials {
    @Override
    public AccessToken refreshAccessToken() throws IOException {
      return new AccessToken("fake-access-token", Date.from(Instant.now().plusSeconds(3600)));
    }

    @Override
    public String getAccount() {
      return "fake-account@google.com";
    }
  }

  static class UnsupportedCredentials extends GoogleCredentials {}

  public GcpLoginCallbackHandler createHandler(GoogleCredentials credentials) throws Exception {
    GcpLoginCallbackHandler gcpLoginCallbackHandler = new GcpLoginCallbackHandler(credentials);
    HashMap configs = new HashMap<String, Object>();
    ArrayList jaasConfig = new ArrayList<AppConfigurationEntry>();
    jaasConfig.add(
        new AppConfigurationEntry(
            "OAuthBearerLoginModule",
            LoginModuleControlFlag.REQUIRED,
            new HashMap<String, String>()));
    gcpLoginCallbackHandler.configure(configs, "OAUTHBEARER", jaasConfig);

    return gcpLoginCallbackHandler;
  }

  @Test
  public void success() throws Exception {
    Instant now = Instant.now();
    OAuthBearerTokenCallback oauthBearerTokenCallback = new OAuthBearerTokenCallback();
    Callback[] callbacks = {oauthBearerTokenCallback};

    GcpLoginCallbackHandler gcpOAuthBearerLoginCallbackHandler = createHandler(new FakeGoogleCredentials());
    gcpOAuthBearerLoginCallbackHandler.handle(callbacks);

    OAuthBearerToken oauthBearerToken = oauthBearerTokenCallback.token();
    SerializedJwt jwtToken = new SerializedJwt(oauthBearerToken.value());

    Map<String, Object> header = OAuthBearerUnsecuredJws.toMap(jwtToken.getHeader());
    Map<String, Object> payload = OAuthBearerUnsecuredJws.toMap(jwtToken.getPayload());

    // Validate the JWT token is as expected by our server.
    assertThat(header.get("typ")).isEqualTo("JWT");
    assertThat(header.get("alg")).isEqualTo("GOOG_OAUTH2_TOKEN");

    assertThat(payload.get("exp")).isInstanceOf(Integer.class);
    assertThat(((int) payload.get("exp"))).isGreaterThan((int) now.getEpochSecond());

    // The signature is the base64 encoded Google OAuth token.
    assertThat(new String(Base64.getUrlDecoder().decode(jwtToken.getSignature()), UTF_8))
        .isEqualTo("fake-access-token");
    assertThat(oauthBearerToken.scope()).isEqualTo(ImmutableSet.of("kafka"));
    assertThat(oauthBearerToken.principalName()).isEqualTo("fake-account@google.com");
  }

  @Test
  public void fail_unsupportedCredentialType() throws Exception {
    OAuthBearerTokenCallback oauthBearerTokenCallback = new OAuthBearerTokenCallback();
    Callback[] callbacks = {oauthBearerTokenCallback};

    GcpLoginCallbackHandler gcpOAuthBearerLoginCallbackHandler = createHandler(new UnsupportedCredentials());
    assertThrows(IOException.class, () -> gcpOAuthBearerLoginCallbackHandler.handle(callbacks));
  }
}
