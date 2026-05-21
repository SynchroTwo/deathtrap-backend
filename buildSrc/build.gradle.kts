plugins {
    `kotlin-dsl`
}

repositories {
    gradlePluginPortal()
    mavenCentral()
}

dependencies {
    // Makes com.github.johnrengelman.shadow.tasks.ShadowJar available
    // for type-safe Kotlin DSL configuration in all subproject build scripts.
    implementation("com.github.johnrengelman:shadow:8.1.1")
    // shadow 8.1.1 drags an old commons-io onto the shared build classpath, which
    // breaks org.owasp.dependencycheck 12.x (needs BOMInputStream.builder(), commons-io >= 2.13).
    // Pin the newer one so buildSrc exports it and the dependency-check analyzers initialize.
    implementation("commons-io:commons-io:2.16.1")
}
