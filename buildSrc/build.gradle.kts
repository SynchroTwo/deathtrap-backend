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
}
