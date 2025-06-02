# Exo Auth

Exo(Employee eXperience Organization) Auth is the authentication service for Exo, supporting HttpOnly cookies, JWT, and OAuth for secure and flexible user authentication. It ensures robust access control and seamless integration across Exo services.

## Features

- **HttpOnly Cookies**: Secure session management to prevent XSS attacks.
- **JWT**: Stateless authentication for scalable and efficient user sessions.
- **OAuth**: Third-party authentication for seamless user onboarding.
- **Access Control**: Role-based and permission-based access management.
- **Integration**: Designed for seamless integration across Exo services.

## Benefits

- **Enhanced Security**: Protects user data with industry-standard authentication mechanisms.
- **Scalability**: Supports stateless authentication for high-performance applications.
- **Flexibility**: Offers multiple authentication methods to suit diverse requirements.
- **Consistency**: Ensures uniform authentication across all Exo services.

## Tech Stack

- ![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) **Java**
- ![Spring Boot](https://img.shields.io/badge/Spring%20Boot-6DB33F?style=for-the-badge&logo=springboot&logoColor=white) **Spring Boot**
- ![Maven](https://img.shields.io/badge/Maven-C71A36?style=for-the-badge&logo=apachemaven&logoColor=white) **Maven**
- ![MySQL](https://img.shields.io/badge/MySQL-4479A1?style=for-the-badge&logo=mysql&logoColor=white) **MySQL**
- ![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white) **JWT**
- ![OAuth](https://img.shields.io/badge/OAuth-3C873A?style=for-the-badge&logo=oauth&logoColor=white) **OAuth**
- ![Git](https://img.shields.io/badge/Git-F05032?style=for-the-badge&logo=git&logoColor=white) **Git**
- ![Microservices](https://img.shields.io/badge/Microservices-FF5733?style=for-the-badge&logo=microservices&logoColor=white) **Microservices**

## Getting Started

### Prerequisites

- **Java**: Ensure Java is installed (version 17 or higher recommended).
- **Maven**: Build and manage dependencies using Maven.

### Installation

Add the following dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>com.exodia_portal</groupId>
    <artifactId>exo-auth</artifactId>
    <version>1.0.0</version>
</dependency>