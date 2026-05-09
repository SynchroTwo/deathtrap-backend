plugins {
    id("org.springframework.boot") version "3.5.6" apply false
    id("io.spring.dependency-management") version "1.1.4" apply false
    id("org.owasp.dependencycheck") version "12.1.0" apply false
}

allprojects {
    group = "in.deathtrap"
    version = "1.0.0"
    repositories {
        mavenCentral()
    }
    apply(plugin = "org.owasp.dependencycheck")
    extensions.configure<org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension> {
        format = "HTML"
        outputDirectory = "${rootProject.buildDir}/reports/dependency-check"
        failBuildOnCVSS = 7.0f
        suppressionFile = "${rootProject.projectDir}/config/owasp-suppressions.xml"
        // NVD API key: set via gradle.properties, NVD_API_KEY env var, or -PnvdApiKey=<key>
        val nvdKey = System.getenv("NVD_API_KEY") ?: (project.findProperty("nvdApiKey") as String?)
        if (!nvdKey.isNullOrBlank()) {
            nvd.apiKey = nvdKey
            nvd.delay = 1000  // ms between NVD API calls — stay well under rate limit
        }
        // OSS Index requires a separate Sonatype account — disable it, NVD is sufficient
        analyzers.ossIndexEnabled = false
        // Checkstyle is a build tool — its transitive deps are never deployed to Lambda
        skipConfigurations = listOf("checkstyle")
    }
}

subprojects {
    apply(plugin = "java")
    apply(plugin = "io.spring.dependency-management")
    apply(plugin = "checkstyle")

    extensions.configure<JavaPluginExtension> {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(21))
        }
    }

    extensions.configure<io.spring.gradle.dependencymanagement.dsl.DependencyManagementExtension> {
        imports {
            mavenBom("org.springframework.boot:spring-boot-dependencies:3.5.6")
        }
        dependencies {
            // CVE-2026-42198, CVE-2025-49146: upgrade postgresql beyond Spring Boot 3.5.6 BOM version
            dependency("org.postgresql:postgresql:42.7.5")
        }
    }

    extensions.configure<CheckstyleExtension> {
        toolVersion = "10.21.0"
        maxWarnings = 0
    }

    tasks.withType<Test> {
        useJUnitPlatform()
    }
}
