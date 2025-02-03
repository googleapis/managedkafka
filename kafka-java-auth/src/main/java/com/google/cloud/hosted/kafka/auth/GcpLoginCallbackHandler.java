/*
 * Copyright 2025 Google LLC
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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.ComputeEngineCredentials;
import com.google.auth.oauth2.ExternalAccountCredentials;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.IdTokenCredentials;
import com.google.auth.oauth2.IdTokenProvider;
import com.google.auth.oauth2.ImpersonatedCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.gson.Gson;
import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;
import org.apache.kafka.common.security.oauthbearer.internals.secured.BasicOAuthBearerToken;

/**
 * A callback handler that provides a Google OAuth token to a Kafka client.
 *
 * <p>This callback handler is used by the Kafka client to authenticate to a Google's Kafka server
 * using OAuth.
 */
public class GcpLoginCallbackHandler implements AuthenticateCallbackHandler {
  private static final String JWT_SUBJECT_CLAIM = "sub";
  private static final String JWT_ISSUED_AT_CLAIM = "iat";
  private static final String JWT_SCOPE_CLAIM = "scope";
  private static final String JWT_EXP_CLAIM = "exp";
  private static final String GOOGLE_CLOUD_PLATFORM_SCOPE =
      "https://www.googleapis.com/auth/cloud-platform";
  private static final JsonFactory JSON_FACTORY = new GsonFactory();
  private static final String TARGET_AUDIENCE = "https://www.googleapis.com/oauth2/v4/token";

  /** A stub Google credentials class that exposes the account name. Used only for testing. */
  abstract static class StubGoogleCredentials extends GoogleCredentials {
    abstract String getAccount();
  }

  private static final String HEADER =
      new Gson().toJson(ImmutableMap.of("typ", "JWT", "alg", "GOOG_OAUTH2_TOKEN"));

  private boolean configured = false;
  private final GoogleCredentials credentials;

  /** Creates a new callback handler using the default application credentials. */
  public GcpLoginCallbackHandler() {
    try {
      this.credentials =
          GoogleCredentials.getApplicationDefault().createScoped(GOOGLE_CLOUD_PLATFORM_SCOPE);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to create Google credentials", e);
    }
  }

  @VisibleForTesting
  GcpLoginCallbackHandler(GoogleCredentials credentials) {
    this.credentials = credentials;
  }

  @Override
  public void configure(
      Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
    if (!Objects.equals(saslMechanism, OAuthBearerLoginModule.OAUTHBEARER_MECHANISM)) {
      throw new IllegalArgumentException(
          String.format("Unexpected SASL mechanism: %s", saslMechanism));
    }
    configured = true;
  }

  private boolean isConfigured() {
    return configured;
  }

  @Override
  public void handle(Callback[] callbacks) throws UnsupportedCallbackException, IOException {
    if (!isConfigured()) {
      throw new IllegalStateException("Callback handler not configured");
    }

    for (Callback callback : callbacks) {
      if (callback instanceof OAuthBearerTokenCallback) {
        handleTokenCallback((OAuthBearerTokenCallback) callback);
      } else {
        throw new UnsupportedCallbackException(callback);
      }
    }
  }

  private void handleTokenCallback(OAuthBearerTokenCallback callback) throws IOException {
    String subject = "";
    // The following credentials are the ones that support the getAccount() or similar method to
    // obtain the principal name. Namely, the ones that can be obtained with two-legged
    // authentication, which do not involve user authentication, such as service account
    // credentials.
    if (credentials instanceof ComputeEngineCredentials) {
      subject = ((ComputeEngineCredentials) credentials).getAccount();
    } else if (credentials instanceof ServiceAccountCredentials) {
      subject = ((ServiceAccountCredentials) credentials).getClientEmail();
    } else if (credentials instanceof ExternalAccountCredentials) {
      subject = ((ExternalAccountCredentials) credentials).getServiceAccountEmail();
    } else if (credentials instanceof ImpersonatedCredentials) {
      subject = ((ImpersonatedCredentials) credentials).getAccount();
    } else if (credentials instanceof StubGoogleCredentials) {
      subject = ((StubGoogleCredentials) credentials).getAccount();
    } else if (credentials instanceof IdTokenProvider) {
      subject = parseGoogleIdToken((IdTokenProvider) credentials).getEmail();
    } else {
      throw new IOException("Unknown credentials type: " + credentials.getClass().getName());
    }
    credentials.refreshIfExpired();
    AccessToken googleAccessToken = credentials.getAccessToken();
    String kafkaToken = getKafkaAccessToken(googleAccessToken, subject);

    Instant now = Instant.now();
    OAuthBearerToken token =
        new BasicOAuthBearerToken(
            kafkaToken,
            ImmutableSet.of("kafka"),
            googleAccessToken.getExpirationTime().toInstant().toEpochMilli(),
            subject,
            now.toEpochMilli());
    callback.token(token);
  }

  private static GoogleIdToken.Payload parseGoogleIdToken(IdTokenProvider credentials) throws IOException{
    return GoogleIdToken.parse(
              JSON_FACTORY,
              IdTokenCredentials.newBuilder()
                  .setTargetAudience(TARGET_AUDIENCE)
                  .setOptions(
                      Arrays.asList(
                          IdTokenProvider.Option.FORMAT_FULL,
                          IdTokenProvider.Option.INCLUDE_EMAIL))
                  .setIdTokenProvider((IdTokenProvider) credentials)
                  .build()
                  .refreshAccessToken()
                  .getTokenValue()).getPayload();
  }

  private static String b64Encode(String data) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(data.getBytes(UTF_8));
  }

  private static String getJwt(AccessToken token, String subject) {
    return new Gson()
        .toJson(
            ImmutableMap.of(
                JWT_EXP_CLAIM,
                token.getExpirationTime().toInstant().getEpochSecond(),
                JWT_ISSUED_AT_CLAIM,
                Instant.now().getEpochSecond(),
                JWT_SCOPE_CLAIM,
                "kafka",
                JWT_SUBJECT_CLAIM,
                subject));
  }

  private static String getKafkaAccessToken(AccessToken token, String subject) {
    return String.join(
        ".",
        b64Encode(HEADER),
        b64Encode(getJwt(token, subject)),
        b64Encode(token.getTokenValue()));
  }

  @Override
  public void close() {}
}

