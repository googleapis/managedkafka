/*
 * Copyright 2024 Google LLC
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

import com.google.auth.oauth2.GoogleCredentials;
import com.google.common.annotations.VisibleForTesting;
import io.confluent.kafka.schemaregistry.client.SchemaRegistryClientConfig;
import io.confluent.kafka.schemaregistry.client.security.bearerauth.BearerAuthCredentialProvider;
import java.io.IOException;
import java.net.URL;
import java.util.Map;
import org.apache.kafka.common.security.oauthbearer.internals.secured.ConfigurationUtils;

/**
 * A Bearer Auth Credential Provider that provides a Google OAuth token to a Schema Registry client.
 *
 * <p>This callback handler is used by the Schema Registry client to authenticate to a Google's
 * Schema Registry server using OAuth.
 */
public class GcpBearerAuthCredentialProvider implements BearerAuthCredentialProvider {

  private static final String GOOGLE_CLOUD_PLATFORM_SCOPE =
      "https://www.googleapis.com/auth/cloud-platform";
  private static final String GCP_ALIAS = "GCP";

  private final GoogleCredentials credentials;
  private String targetSchemaRegistry;
  private String targetIdentityPoolId;

  /** Creates a new credential provider using the default application credentials. */
  public GcpBearerAuthCredentialProvider() {
    try {
      this.credentials =
          GoogleCredentials.getApplicationDefault().createScoped(GOOGLE_CLOUD_PLATFORM_SCOPE);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to create Google credentials", e);
    }
  }

  @VisibleForTesting
  public GcpBearerAuthCredentialProvider(GoogleCredentials credentials) {
    this.credentials = credentials;
  }

  @Override
  public String alias() {
    return GCP_ALIAS;
  }

  @Override
  public String getTargetSchemaRegistry() {
    return this.targetSchemaRegistry;
  }

  @Override
  public String getTargetIdentityPoolId() {
    return this.targetIdentityPoolId;
  }

  @Override
  public String getBearerToken(URL url) {
    String tokenValue;
    try {
      this.credentials.refreshIfExpired();
      tokenValue = this.credentials.getAccessToken().getTokenValue();
    } catch (IOException e) {
      throw new IllegalStateException("Failed to refresh or fetch Google credentials ", e);
    }
    return tokenValue;
  }

  @Override
  public void configure(Map<String, ?> configs) {
    ConfigurationUtils cu = new ConfigurationUtils(configs);
    this.targetSchemaRegistry =
        cu.validateString(SchemaRegistryClientConfig.BEARER_AUTH_LOGICAL_CLUSTER, false);
    this.targetIdentityPoolId =
        cu.validateString(SchemaRegistryClientConfig.BEARER_AUTH_IDENTITY_POOL_ID, false);
  }
}
