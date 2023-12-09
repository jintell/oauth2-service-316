# Getting Started

### Spring Authorization Server

This application is based on Spring Boot app using spring boot 3.1.6, gradle build tool and java 17.

1. It uses the latest gradle artifact `spring-boot-starter-oauth2-authorization-server`, 
2. `postgres` drivers for connections to postgres database,
3. `Spring reactive web flux` to run the application as micro service,
4. `Eureka client` for service registration and discovery, 
5. `Spring cloud config client` to get configuration from a central config server.
6. `Spring Data JPA` for modeling the database entity and perform database operations,
7. `spring-security-oauth2-jose` for assisting with encoding/decoding JWT tokens,
8. `Micrometer prometheus` and `spring actuator` to expose metrics endpoint for monitoring the health of the application

The application is configured to Obtain access token in the following use cases:
1. Obtain access token based on the client credentials grant flow passing the basic auth client Id and secret,
2. Obtain access token with public Id add to tokens claims providing base 64 encoded username:password along with the 
basic auth client Id and secret for the client credentials grant flow.
3. Obtain access token using the authorization code grant flow using PKCE to strengthen the security. 

# Build the artifact

`./gradlew clean build`

# Run the built Authorization Server

`java -jar build/libs/authorization_latest-1-SNAPSHOT.jar`

# Alternatively, Build and Run with a Single maven command.

`./gradlew spring-boot:run`

**Note:** This option will not build the artifact (authorization_latest0-1-SNAPSHOT.jar) for you

# Stop the server

`./gradlew spring-boot:run`

**Note:** This option will not build the artifact (authorization_latest0-1-SNAPSHOT.jar) for you

### Guides

The following guides illustrate how to use some features concretely:

* [Building a Reactive RESTful Web Service](https://spring.io/guides/gs/reactive-rest-service/)
* [Building a RESTful Web Service with Spring Boot Actuator](https://spring.io/guides/gs/actuator-service/)
* [Securing a Web Application](https://spring.io/guides/gs/securing-web/)
* [Spring Boot and OAuth2](https://spring.io/guides/tutorials/spring-boot-oauth2/)
* [Authenticating a User with LDAP](https://spring.io/guides/gs/authenticating-ldap/)
* [Accessing Data with JPA](https://spring.io/guides/gs/accessing-data-jpa/)
* [Service Registration and Discovery with Eureka and Spring Cloud](https://spring.io/guides/gs/service-registration-and-discovery/)
