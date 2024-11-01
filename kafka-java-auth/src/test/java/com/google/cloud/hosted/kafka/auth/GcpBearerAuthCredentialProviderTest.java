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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.util.Date;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit test for GcpBearerAuthCredentialProvider. */
@RunWith(JUnit4.class)
public class GcpBearerAuthCredentialProviderTest {

  private static String FAKE_ACESS_TOKEN = "fake-access-token";

  static class FakeGoogleCredentials extends GoogleCredentials {
    @Override
    public AccessToken refreshAccessToken() throws IOException {
      return new AccessToken(FAKE_ACESS_TOKEN, Date.from(Instant.now().plusSeconds(3600)));
    }
  }

  static class UnsupportedCredentials extends GoogleCredentials {}

  private GcpBearerAuthCredentialProvider createProvider(GoogleCredentials credentials) {
    GcpBearerAuthCredentialProvider gcpBearerAuthCredentialProvider =
        new GcpBearerAuthCredentialProvider(credentials);
    return gcpBearerAuthCredentialProvider;
  }

  @Test
  public void success() throws MalformedURLException {
    GcpBearerAuthCredentialProvider gcpBearerAuthCredentialProvider =
        createProvider(new FakeGoogleCredentials());
    String token = gcpBearerAuthCredentialProvider.getBearerToken(new URL("https://test"));

    // Validate the token.
    assertEquals(FAKE_ACESS_TOKEN, token);
  }

  @Test
  public void failure() throws MalformedURLException {
    GcpBearerAuthCredentialProvider gcpBearerAuthCredentialProvider =
        createProvider(new UnsupportedCredentials());

    // Validate the token.
    assertThrows(
        IllegalStateException.class,
        () -> gcpBearerAuthCredentialProvider.getBearerToken(new URL("https://test")));
  }
}
