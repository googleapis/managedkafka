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

package io.confluent.kafka.schemaregistry.client.rest.entities;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.junit.Before;
import org.junit.Test;

public class ErrorMessageTest {
  private JsonMapper mapper;

  @Before
  public void setup() {
    this.mapper = JsonMapper.builder()
        .enable(JsonReadFeature.ALLOW_NON_NUMERIC_NUMBERS)
        .build();
  }

  @Test
  public void success_parseUnnestedFields() throws Exception {
    String json = "{\n"
        + "  \"error_code\": 401,\n"
        + "  \"message\": \"parseUnnestedFields\"\n"
        + "}";

    ErrorMessage em = mapper.readValue(json, ErrorMessage.class);

    assertThat(em).isNotNull();
    assertThat(em.getErrorCode()).isEqualTo(401);
    assertThat(em.getMessage()).isEqualTo("parseUnnestedFields");
  }

  @Test
  public void success_parseNestedFieldsWithStatus() throws Exception {
    String json = "{\n"
        + "  \"error\": {\n"
        + "    \"code\": 402,\n"
        + "    \"message\": \"parseNestedFields\",\n"
        + "    \"status\": \"FAILED_PRECONDITION\"\n"
        + "  }\n"
        + "}";

    ErrorMessage em = mapper.readValue(json, ErrorMessage.class);

    assertThat(em).isNotNull();
    assertThat(em.getErrorCode()).isEqualTo(402);
    assertThat(em.getMessage()).isEqualTo("FAILED_PRECONDITION: parseNestedFields");
  }

  @Test
  public void success_parseNestedFieldsWithoutStatus() throws Exception {
    String json = "{\n"
        + "  \"error\": {\n"
        + "    \"code\": 402,\n"
        + "    \"message\": \"parseNestedFields\"\n"
        + "  }\n"
        + "}";

    ErrorMessage em = mapper.readValue(json, ErrorMessage.class);

    assertThat(em).isNotNull();
    assertThat(em.getErrorCode()).isEqualTo(402);
    assertThat(em.getMessage()).isEqualTo("parseNestedFields");
  }

  @Test
  public void success_parseNestedFieldsWithoutMessage() throws Exception {
    String json = "{\n"
        + "  \"error\": {\n"
        + "    \"code\": 402,\n"
        + "    \"status\": \"FAILED_PRECONDITION\"\n"
        + "  }\n"
        + "}";

    ErrorMessage em = mapper.readValue(json, ErrorMessage.class);

    assertThat(em).isNotNull();
    assertThat(em.getErrorCode()).isEqualTo(402);
    assertThat(em.getMessage()).isEqualTo("FAILED_PRECONDITION");
  }

  @Test
  public void success_parseNestedAndUnnestedFields() throws Exception {
    String json = "{\n"
        + "  \"error_code\": 401,\n"
        + "  \"message\": \"parseUnnestedFields\",\n"
        + "  \"error\": {\n"
        + "    \"code\": 402,\n"
        + "    \"message\": \"parseNestedFields\",\n"
        + "    \"status\": \"FAILED_PRECONDITION\"\n"
        + "  }\n"
        + "}";

    ErrorMessage em = mapper.readValue(json, ErrorMessage.class);

    assertThat(em).isNotNull();
    assertThat(em.getErrorCode()).isEqualTo(402);
    assertThat(em.getMessage()).isEqualTo("FAILED_PRECONDITION: parseNestedFields");
  }

  @Test
  public void fail_badJsonFormat() {
    String json = "{\n"
        + "  \"error\": {\n"
        + "    \"code\": 402\n"
        + "    \"message\": \"parseNestedFields\"\n"
        + "  }\n"
        + "}";

    assertThrows(JsonMappingException.class, () -> mapper.readValue(json, ErrorMessage.class));
  }
}