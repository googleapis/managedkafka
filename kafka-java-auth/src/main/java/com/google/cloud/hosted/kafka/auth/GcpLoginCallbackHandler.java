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
import com.google.common.flogger.GoogleLogger;
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
  public static final String JWT_SUBJECT_CLAIM = "sub";
  public static final String JWT_ISSUED_AT_CLAIM = "iat";
  public static final String JWT_SCOPE_CLAIM = "scope";
  public static final String JWT_EXP_CLAIM = "exp";
  
  public static final JsonFactory JSON_FACTORY = new GsonFactory();
  public static final String TARGET_AUDIENCE = "https://www.googleapis.com/oauth2/v4/token";
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  /** A stub Google credentials class that exposes the account name. Used only for testing. */
  public abstract static class StubGoogleCredentials extends GoogleCredentials {
    abstract String getAccount();
  }

  public static final String GOOGLE_CLOUD_PLATFORM_SCOPE =
      "https://www.googleapis.com/auth/cloud-platform";
  private static final String HEADER =
      new Gson().toJson(ImmutableMap.of("typ", "JWT", "alg", "GOOG_OAUTH2_TOKEN"));

  private boolean configured = false;
  private final GoogleCredentials credentials;

  public GcpLoginCallbackHandler() {
    try {
      logger.atInfo().log("Creating Google credentials");
      this.credentials =
          GoogleCredentials.getApplicationDefault().createScoped(GOOGLE_CLOUD_PLATFORM_SCOPE);
      logger.atInfo().log("Created Google credentials");
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
      if (callback instanceof OAuthBearerTokenCallback oAuthBearerTokenCallback) {
        handleTokenCallback(oAuthBearerTokenCallback);
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
    logger.atInfo().log("Parsing %s", credentials.getClass().getName());
    if (credentials instanceof ComputeEngineCredentials computeEngineCredentials) {
      logger.atInfo().log("Parsing instance of ComputeEngineCredentials");
      subject = computeEngineCredentials.getAccount();
    } else if (credentials instanceof ServiceAccountCredentials serviceAccountCredentials) {
      logger.atInfo().log("Parsing instance of ServiceAccountCredentials");
      subject = serviceAccountCredentials.getClientEmail();
    } else if (credentials instanceof ExternalAccountCredentials externalAccountCredentials) {
      logger.atInfo().log("Parsing instance of ExternalAccountCredentials");
      subject = externalAccountCredentials.getServiceAccountEmail();
    } else if (credentials instanceof ImpersonatedCredentials impersonatedCredentials) {
      logger.atInfo().log("Parsing instance of ImpersonatedCredentials");
      subject = impersonatedCredentials.getAccount();
    } else if (credentials instanceof StubGoogleCredentials stubGoogleCredentials) {
      subject = stubGoogleCredentials.getAccount();
      logger.atInfo().log("Parsed instance of StubGoogleCredentials, got email: %s", subject);
    } else if (credentials instanceof IdTokenProvider idTokenProvider) {
      logger.atInfo().log("Parsing instance of IdTokenProvider");
      subject = parseGoogleIdToken(idTokenProvider).getEmail();
    } else {
      throw new IOException("Unknown credentials type: " + credentials.getClass().getName());
    }
    logger.atInfo().log("Refreshing credentials for subject: %s", subject);
    credentials.refreshIfExpired();
    var googleAccessToken = credentials.getAccessToken();
    logger.atInfo().log("Google access token: %s", googleAccessToken);
    String kafkaToken = getKafkaAccessToken(googleAccessToken, subject);
    logger.atInfo().log("Kafka token: %s", kafkaToken);
    var now = Instant.now();
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

