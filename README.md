# Exo Auth

Exo(Employee eXperience Organization) Auth is the authentication service for Exo, supporting HttpOnly cookies, JWT, and OAuth for secure and flexible user authentication. It ensures robust access control and seamless integration across Exo services.

---

## Features

- **HttpOnly Cookies**: Secure session management to prevent XSS attacks.
- **JWT**: Stateless authentication for scalable and efficient user sessions.
- **OAuth**: Third-party authentication for seamless user onboarding.
- **Access Control**: Role-based and permission-based access management.
- **Integration**: Designed for seamless integration across Exo services.

---

## Benefits

- **Enhanced Security**: Protects user data with industry-standard authentication mechanisms.
- **Scalability**: Supports stateless authentication for high-performance applications.
- **Flexibility**: Offers multiple authentication methods to suit diverse requirements.
- **Consistency**: Ensures uniform authentication across all Exo services.

---

## Tech Stack

- ![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) **Java**
- ![Spring Boot](https://img.shields.io/badge/Spring%20Boot-6DB33F?style=for-the-badge&logo=springboot&logoColor=white) **Spring Boot**
- ![Maven](https://img.shields.io/badge/Maven-C71A36?style=for-the-badge&logo=apachemaven&logoColor=white) **Maven**
- ![MySQL](https://img.shields.io/badge/MySQL-4479A1?style=for-the-badge&logo=mysql&logoColor=white) **MySQL**
- ![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white) **JWT**
- ![OAuth](https://img.shields.io/badge/OAuth-3C873A?style=for-the-badge&logo=oauth&logoColor=white) **OAuth**
- ![Git](https://img.shields.io/badge/Git-F05032?style=for-the-badge&logo=git&logoColor=white) **Git**
- ![Microservices](https://img.shields.io/badge/Microservices-FF5733?style=for-the-badge&logo=microservices&logoColor=white) **Microservices**

---

## Getting Started

### Prerequisites

- **Java**: Ensure Java is installed (version 17 or higher recommended).
- **Maven**: Build and manage dependencies using Maven.

---

### Installation

Add the following dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>com.exodia_portal</groupId>
    <artifactId>exo-auth</artifactId>
    <version>1.0.0</version>
</dependency>
```


---

## Setup

### Configuring `application.yml`

To set up the application, create an `application.yml` file in the `src/main/resources` directory with the following structure:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope: profile, email
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
          github:
            client-id: ${GITHUB_CLIENT_ID}
            client-secret: ${GITHUB_CLIENT_SECRET}
            scope: read:user, user:email
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
  datasource:
    name: dev-server
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/exo-portal
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: "true"
    database-platform: org.hibernate.dialect.MySQL8Dialect
server:
  port: 8080
jwt:
  secret: ${JWT_SECRET}
  access:
    expiration: 3600000
  refresh:
    expiration: 86400000
```

---

**Environment Variables**

| Variable Name         | Description                          |
|-----------------------|--------------------------------------|
| `GOOGLE_CLIENT_ID`    | Google OAuth client ID              |
| `GOOGLE_CLIENT_SECRET`| Google OAuth client secret          |
| `GITHUB_CLIENT_ID`    | GitHub OAuth client ID              |
| `GITHUB_CLIENT_SECRET`| GitHub OAuth client secret          |
| `DB_USERNAME`         | MySQL database username             |
| `DB_PASSWORD`         | MySQL database password             |
| `JWT_SECRET`          | Secret key for signing JWT tokens   |