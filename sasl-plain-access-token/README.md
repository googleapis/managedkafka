# SASL/PLAIN Access Token Client Examples

This directory contains client library extensions and examples on showing how to use SASL/Plain authentication with GMK using [Access Tokens](https://cloud.google.com/docs/authentication/token-types#access) - as an alternative to using base64 encoded Service Account Keys.

Unlike Service Account Keys - Access Tokens frequently change and are only valid for 60 minutes by default. GMK validates SASL/Plain credentials at the establishment of every new [Kafka Wire Protocol](https://kafka.apache.org/090/protocol.html) connection, therefore special care is required to ensure that the client library always presents a valid Access Token at connection establihment.

Where possible - you should use [OAuthBearer authentication](https://cloud.google.com/managed-service-for-apache-kafka/docs/authentication-kafka#oauthbearer) instead of SASL/Plain - but these implementations can be a useful alternative where this is not possible.

## Implementations

| Implementation                                                           | Language | Description                                                                                                                                                                                                                                                 |
| ------------------------------------------------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [segmentio/saslplainoauthmechanism](./segmentio/saslplainoauthmechanism) | Go       | An implementation of the [sasl.Mechanism](https://github.com/segmentio/kafka-go/blob/main/sasl/sasl.go#L13-L29) interface that allows you to use SASL/PLAIN with Access Tokens with the [segmentio/kafka-go](https://github.com/segmentio/kafka-go) library |
