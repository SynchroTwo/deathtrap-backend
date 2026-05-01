plugins { id("org.springframework.boot") }
dependencies {
    implementation(project(":packages:common-types"))
    implementation(project(":packages:common-errors"))
    implementation(project(":packages:common-db"))
    implementation(project(":packages:common-audit"))
    implementation("org.springframework.boot:spring-boot-starter-data-jdbc")
    implementation("com.amazonaws:aws-lambda-java-events:3.11.4")
    implementation("com.amazonaws:aws-lambda-java-core:1.2.3")
    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")
}
tasks.named<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
    archiveBaseName.set("sqs-consumer"); archiveVersion.set("1.0.0"); archiveClassifier.set("all")
}
