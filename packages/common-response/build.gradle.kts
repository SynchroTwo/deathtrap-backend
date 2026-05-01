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
}
