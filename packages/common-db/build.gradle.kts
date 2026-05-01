plugins {
    java
}

dependencies {
    implementation(project(":packages:common-errors"))
    implementation("org.springframework.boot:spring-boot-starter-data-jdbc")
    runtimeOnly("org.postgresql:postgresql")
    implementation("org.flywaydb:flyway-core")
}
