plugins {
    java
}

dependencies {
    implementation(project(":packages:common-types"))
    implementation(project(":packages:common-db"))
    implementation(project(":packages:common-crypto"))
    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("org.springframework.boot:spring-boot-starter-data-jdbc")
    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")
}
