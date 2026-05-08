plugins {
    java
    `java-test-fixtures`
}

dependencies {
    implementation(project(":packages:common-errors"))
    implementation("org.springframework.boot:spring-boot-starter-data-jdbc")
    runtimeOnly("org.postgresql:postgresql")
    implementation("org.flywaydb:flyway-core")

    testFixturesImplementation("org.springframework.boot:spring-boot-starter-data-jdbc")
    testFixturesImplementation("org.flywaydb:flyway-core")
    testFixturesImplementation("io.zonky.test:embedded-postgres:2.0.6")
    testFixturesImplementation("org.junit.jupiter:junit-jupiter-api")
    testFixturesImplementation(project(":packages:common-errors"))
}
