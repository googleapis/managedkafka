# Google Cloud Managed Service for Apache Kafka[TM] Client Auth

Client-side Kafka software libraries enabling authentication with Google Cloud Managed Service for Apache Kafka. These libraries allow you to authenticate with the service using [application default credentials](http://cloud/docs/authentication/provide-credentials-adc). This is a safer and simpler authentication mechanism than using service account keys directly. The method relies on Google's OAuth via Kafka's OAUTHBEARER mechanism.

The following presents two alternatives for configuring [Kafka Confluent clients](https://docs.confluent.io/platform/current/clients/index.html) to use Google's authentication mechanisms in order to connect with clusters deployed using the Managed Service for Apache Kafka.

The first alternative is suited for Java clients where you have the ability to modify the client classpath to include the authentication libraries.

The second alternative offers a solution for non-Java Kafka clients, but requires you to set up a local authentication server. This server's role is to securely exchange your application's default credentials with the Kafka client, enabling authentication and authorization for accessing the Kafka cluster.

In either case, your client leverages Google Auth libraries for authentication using default environment credentials. On GCP environments like GKE or GCE, this typically implies using the environment service accounts. You can override this behavior and specify different credentials using the GOOGLE_APPLICATION_CREDENTIALS environment variable, as detailed in [this article](https://github.com/googleapis/google-auth-library-java?tab=readme-ov-file#getting-application-default-credentials).

Authentication is not supported for clients using [Workload Identity Federation for GKE](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity). As an alternative, [link Kubernetes service accounts to IAM service accounts](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity#kubernetes-sa-to-iam).

## Kafka Java Auth Client Handler

Inside kafka-java-auth, you'll find an implementation of Kafka's [AuthenticateCallbackHandler](https://kafka.apache.org/20/javadoc/org/apache/kafka/common/security/auth/AuthenticateCallbackHandler.html) that is suited to have your Kafka clients authenticate with Google Cloud Managed Service for Apache Kafka clusters.

Follow these two steps below to get your client setup.

1. The library is available on Maven. Find instructions on how to add it to your project, tailored to your specific build system, [here](https://central.sonatype.com/artifact/com.google.cloud.hosted.kafka/managed-kafka-auth-login-handler).

2. Configure your Kafka client, including the following client authentication properties.
```
security.protocol=SASL_SSL
sasl.mechanism=OAUTHBEARER
sasl.login.callback.handler.class=com.google.cloud.hosted.kafka.auth.GcpLoginCallbackHandler
sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required;
```

## Local Auth Server

Inside kafka-auth-local-server, you'll find a python script that let you run a local auth server that similarly to the Java library above, enables the Kafka clients to authenticate using the environment default credentials.

In order to use this library, you should:

1. Create a virtual python environment and install the server dependencies.
```
pip install virtualenv
virtualenv <your-env>
source <your-env>/bin/activate
<your-env>/bin/pip install -r kafka-auth-local-server/requirements.txt
```

2. Run the server.
```
kafka-auth-local-server/kafka_gcp_credentials_server.py
```
It should print a line like `Serving on localhost:14293. This is not accessible outside of the current machine.`

3. Configure your client to authenticate against the server

For Java, you'll use the following authentication client properties:
```
security.protocol=SASL_SSL
sasl.mechanism=OAUTHBEARER
sasl.oauthbearer.token.endpoint.url=http://localhost:14293
sasl.login.callback.handler.class=org.apache.kafka.common.security.oauthbearer.secured.OAuthBearerLoginCallbackHandler
sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule \
  required clientId="admin" clientSecret="unused";
```

For Python, you can initialize your client as follows:
```
...

conf = {
    'bootstrap.servers': '<BOOTSTRAP_SERVER_ADDRESS>',
    'security.protocol': 'SASL_SSL',
    'sasl.mechanisms': 'OAUTHBEARER',
    'sasl.oauthbearer.token.endpoint.url': 'localhost:14293',
    'sasl.oauthbearer.client.id': 'unused',
    'sasl.oauthbearer.client.secret': 'unused',
    'sasl.oauthbearer.method': 'oidc',
}

producer = Producer(conf)
...
```

For Golang, you'll initialize your client as follows:
```
...
p, err := kafka.NewProducer(&kafka.ConfigMap{
    // User-specific properties that you must set
    "bootstrap.servers": "<BOOTSTRAP_SERVER_ADDRESS>",
    "security.protocol": "SASL_SSL",
    "sasl.mechanisms": "OAUTHBEARER",
    "sasl.oauthbearer.token.endpoint.url": "localhost:14293",
    "sasl.oauthbearer.client.id": "unused",
    "sasl.oauthbearer.client.secret": "unused",
    "sasl.oauthbearer.method": "oidc",})
...
```

For DotNet, the initialization will go as follows:
```
var config = new ProducerConfig
{
    // User-specific properties that you must set
    BootstrapServers = "<BOOTSTRAP SERVERS>",
    SecurityProtocol = SecurityProtocol.SaslSsl,
    SaslMechanism    = SaslMechanism.OAuthBearer,
    SaslOauthbearerTokenEndpointUrl = "localhost:14293",
    SaslOauthbearerMethod = SaslOauthbearerMethod.Oidc,
    SaslOauthbearerClientId = 'unused',
    SaslOauthbearerClientSecret = 'unused',
};

using (var producer = new ProducerBuilder<Null, string>(config).Build())
{
    ...
}
```

For NodeJs, with an initialization as follows:
```
const config = {
  'bootstrap.servers': '<BOOTSTRAP SERVERS>',
  'security.protocol': 'SASL_SSL',
  'sasl.mechanisms': 'OAUTHBEARER',
  'sasl.oauthbearer.token.endpoint.url': 'localhost:14293',
  'sasl.oauthbearer.client.id': 'unused',
  'sasl.oauthbearer.client.secret': 'unused',
  'sasl.oauthbearer.method': 'oidc',

  // Needed for delivery callback to be invoked
  'dr_msg_cb': true
}


const producer = await createProducer(config, (err, report) => {
  ...
});

...
```

* *Apache Kafka is a registered trademark owned by the Apache Software Foundation.*

