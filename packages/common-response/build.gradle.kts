plugins {
    java
}

dependencies {
    implementation(project(":packages:common-types"))
    implementation(project(":packages:common-errors"))
    implementation("com.amazonaws:aws-lambda-java-events:3.11.4")
    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")
    implementation("org.slf4j:slf4j-api")
    // Compile-only: the shared CorsConfig references Spring web/boot types. Every HTTP
    // service that depends on this module already provides them at runtime via
    // spring-boot-starter-web; keep them off this module's runtime classpath.
    compileOnly("org.springframework.boot:spring-boot-starter-web")
}
