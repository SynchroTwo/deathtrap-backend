plugins { id("org.springframework.boot") }
dependencies {
    implementation(project(":packages:common-types"))
    implementation(project(":packages:common-errors"))
    implementation(project(":packages:common-db"))
    implementation(project(":packages:common-audit"))
    implementation(project(":packages:common-crypto"))
    implementation("org.springframework.boot:spring-boot-starter-data-jdbc")
    implementation("com.amazonaws:aws-lambda-java-events:3.11.4")
    implementation("com.amazonaws:aws-lambda-java-core:1.2.3")
    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("software.amazon.awssdk:sqs:2.26.31")
    implementation("software.amazon.awssdk:sns:2.26.31")
    implementation("software.amazon.awssdk:url-connection-client:2.26.31")
    implementation("net.logstash.logback:logstash-logback-encoder:8.0")
    implementation("com.amazonaws:aws-xray-recorder-sdk-core:2.18.0")
    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.mockito:mockito-core")
    testImplementation("org.mockito:mockito-junit-jupiter")
}
tasks.named<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
    archiveBaseName.set("sqs-consumer"); archiveVersion.set("1.0.0"); archiveClassifier.set("all")
}
