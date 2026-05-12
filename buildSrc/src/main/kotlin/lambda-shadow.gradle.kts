plugins {
    id("com.github.johnrengelman.shadow")
}

tasks.named("bootJar") { enabled = false }
tasks.named("jar") { enabled = true }

tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar") {
    archiveBaseName.set(project.name)
    archiveVersion.set("1.0.0")
    archiveClassifier.set("all")
    mergeServiceFiles()
    transform(com.github.jengelman.gradle.plugins.shadow.transformers.AppendingTransformer::class.java) {
        resource = "META-INF/spring.factories"
    }
    transform(com.github.jengelman.gradle.plugins.shadow.transformers.AppendingTransformer::class.java) {
        resource = "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports"
    }
    transform(com.github.jengelman.gradle.plugins.shadow.transformers.AppendingTransformer::class.java) {
        resource = "META-INF/spring/org.springframework.boot.env.EnvironmentPostProcessor"
    }
    transform(com.github.jengelman.gradle.plugins.shadow.transformers.AppendingTransformer::class.java) {
        resource = "META-INF/spring/org.springframework.context.ApplicationContextInitializer"
    }
    transform(com.github.jengelman.gradle.plugins.shadow.transformers.AppendingTransformer::class.java) {
        resource = "META-INF/spring/org.springframework.boot.SpringApplicationRunListener"
    }
    exclude("META-INF/*.DSA", "META-INF/*.RSA", "META-INF/*.SF")
}
