# Google Cloud Managed Service for Apache Kafka[TM] Client Auth

Client-side Kafka software libraries enabling authentication with Google Cloud Managed Service for Apache Kafka. These libraries allow you to authenticate with the service using [application default credentials](http://cloud/docs/authentication/provide-credentials-adc). This is a safer and simpler authentication mechanism than using service account keys directly. The method relies on Google's OAuth via Kafka's OAUTHBEARER mechanism.

The following presents two alternatives for configuring your Kafka clients to use Google's authentication mechanisms in order to connect with clusters deployed using the Managed Service for Apache Kafka.

The first alternative is suited for Java clients where you have the ability to modify the client classpath to include the authentication libraries.

The second alternative works with other clients beyond Java, it requires you running a local authentication server.

## Kafka Java Auth Client Handler

Inside kafka-java-auth, you'll find an implementation of Kafka's [AuthenticateCallbackHandler](https://kafka.apache.org/20/javadoc/org/apache/kafka/common/security/auth/AuthenticateCallbackHandler.html) that is suited to have your Kafka clients authenticate with Google Cloud Managed Service for Apache Kafka clusters.

Follow the steps below to get your client setup.

1. Build the supporting JAR.
```
cd kafka-java-auth
mvn install
```

The relevant artifact will be generated and placed in your local maven repository. 

2. Then you can include the following dependency in your build to include the library along with its dependencies.
```
<dependency>
    <groupId>com.google.cloud.hosted.kafka</groupId>
    <artifactId>managed-kafka-auth-login-handler</artifactId>
    <version>1.0.0</version>
</dependency>
```

3. Configure your Kafka client, including the following authentication properties.
```
security.protocol=SASL_SSL
sasl.mechanism=OAUTHBEARER
sasl.login.callback.handler.class=com.google.cloud.hosted.kafka.auth.GcpLoginCallbackHandler
sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required;
```

With above configuration your client should use the Google Auth Java library in order to authenticate using the default environment credentials. By default on GCP environments such as GKE or GCE, it means the library will use the environment default credentials. This behavior can be modified to point to different credentials via the GOOGLE_APPLICATION_CREDENTIALS environment variable as described in [this article](https://github.com/googleapis/google-auth-library-java?tab=readme-ov-file#getting-application-default-credentials).

## Local Auth Server

Inside kafka-auth-local-server, you'll find a python script that let you run a local auth server that similarly to the Java library above, enables the Kafka clients to authenticate using the environment default credentials.

In order to use this library, you should:

1. Create a virtual python environment and install the server dependencies.
```
pip install virtualenv
virtualenv <your-env>
source <your-env>/bin/activate
<your-env>/bin/pip install packaging
<your-env>/bin/pip install urllib3
<your-env>/bin/pip install google-auth
```

2. Run the server.
```
kafka-auth-local-server/kafka_gcp_credentials_server.py
```
It should print a line like `Serving on localhost:14293. This is not accessible outside of the current machine.`

3. Configure your client, including the following authentication properties.
```
security.protocol=SASL_SSL
sasl.mechanism=OAUTHBEARER
sasl.oauthbearer.token.endpoint.url=http://localhost:14293
sasl.login.callback.handler.class=org.apache.kafka.common.security.oauthbearer.secured.OAuthBearerLoginCallbackHandler
sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule \
  required clientId="admin" clientSecret="unused";
```

* *Apache Kafka is a registered trademark owned by the Apache Software Foundation.*

