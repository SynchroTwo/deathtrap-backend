plugins {
    java
}

dependencies {
    implementation(project(":packages:common-types"))
    implementation(project(":packages:common-errors"))
    implementation(project(":packages:common-db"))
    implementation(project(":packages:common-audit"))
    implementation("org.springframework.boot:spring-boot-starter")
    implementation("org.springframework.boot:spring-boot-starter-data-jdbc")
    implementation("software.amazon.awssdk:ses:2.26.31")
    implementation("io.jsonwebtoken:jjwt-api:0.12.5")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.5")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.5")
}
