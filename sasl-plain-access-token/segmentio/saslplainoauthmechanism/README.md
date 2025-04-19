# saslplainoauthmechanism

saslplainoauthmechanism provides an implementation of the [sasl.Mechanism](https://github.com/segmentio/kafka-go/blob/main/sasl/sasl.go#L13-L29) interface from [segmentio/kafka-go](https://github.com/segmentio/kafka-go) that handles authentication to Google Managed Kafka using OAuth Tokens from [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials).

It allows you to use Authorization Tokens with SASL/Plain in [segmentio/kafka-go](https://github.com/segmentio/kafka-go), without requiring OAuthBearer support in the library.

## Supported Credential Types

saslplainoauthmechanism supports the following Application Default credential types:

1. [GKE Workload Identity Federation](https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity).
2. [Metadata Server Credentials](https://cloud.google.com/docs/authentication/application-default-credentials#attached-sa) - Such as Google Compute Engine, Cloud Run, etc.
3. [gcloud CLI Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials#personal). Specifically the following subset:
    1. `user_credentials` (`gcloud auth application-default login`).
    1. `impersonated_service_account` (`gcloud auth application-default login --impersonate-service-account=<sa email>`).
    1. Other credential types, including `service_account` keys are intentionally unsupported. To use Service Account Keys see [here](https://cloud.google.com/managed-service-for-apache-kafka/docs/authentication-kafka#sasl-plain).


## Usage

1. Ensure you have granted the principal the Managed Kafka Client Role (see [here](https://cloud.google.com/managed-service-for-apache-kafka/docs/authentication-kafka#grant-role)).

2. Create a Mechanism and pass it to the dialer.

    ```go
    package main

    import (
        "context"
        "crypto/tls"
        "log"

        "github.com/googleapis/managedkafka/sasl-plain-access-token/segmentio/saslplainoauthmechanism"
        "github.com/segmentio/kafka-go"
    )

    func main() {

        var bootStrapURL = "<broker FQDN>:9092"
        var topicName = "gmk-test"

        mechanism, err := saslplainoauthmechanism.NewADCMechanism(context.Background())
        if err != nil {
            log.Fatalf("Error creating mechanism: %v\n", err)
        }

        dialer := &kafka.Dialer{
            SASLMechanism: mechanism,
            TLS:           &tls.Config{},
        }

        w := kafka.NewWriter(kafka.WriterConfig{
            Brokers: []string{bootStrapURL},
            Topic:   topicName,
            Dialer:  dialer,
        })

        if err := w.WriteMessages(context.Background(), kafka.Message{Key: []byte("Key-A"), Value: []byte("Hello World!")}); err != nil {
            log.Fatalf("error writing message %v", err)
        }

    }
    ```

3. You can optionally provide your own [TokenSource](https://pkg.go.dev/golang.org/x/oauth2#TokenSource) and principal email:
    ```go
    package main

    import (
        "context"
        "crypto/tls"
        "log"

        "github.com/googleapis/managedkafka/sasl-plain-access-token/segmentio/saslplainoauthmechanism"
        "github.com/segmentio/kafka-go"
        "golang.org/x/oauth2/google"
    )

    func main() {

        var bootStrapURL = "<broker FQDN>:9092"
        var topicName = "gmk-test"

        // Any TokenSource https://pkg.go.dev/golang.org/x/oauth2#TokenSource
        manualTokenSource, err := google.FindDefaultCredentials(context.Background(), "https://www.googleapis.com/auth/cloud-platform")
        if err != nil {
            log.Fatalf("error finding credentials: %v\n", err)
        }

        mechanism, err := saslplainoauthmechanism.NewMechanismWithTokenSource(context.Background(), manualTokenSource.TokenSource, "principal-email@example.com")
        if err != nil {
            log.Fatalf("Error creating mechanism: %v\n", err)
        }

        dialer := &kafka.Dialer{
            SASLMechanism: mechanism,
            TLS:           &tls.Config{},
        }

        w := kafka.NewWriter(kafka.WriterConfig{
            Brokers: []string{bootStrapURL},
            Topic:   topicName,
            Dialer:  dialer,
        })

        if err := w.WriteMessages(context.Background(), kafka.Message{Key: []byte("Key-A"), Value: []byte("Hello World!")}); err != nil {
            log.Fatalf("error writing message %v", err)
        }

    }
    ```
