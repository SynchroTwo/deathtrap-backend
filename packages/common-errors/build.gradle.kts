plugins {
    java
}

dependencies {
    implementation(project(":packages:common-types"))
    implementation("org.springframework.boot:spring-boot-starter-web")
    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")
}
