// Set default version and group
group = "com.github.incept5"  // Default group for JitPack compatibility

// Determine the version to use
val providedVersion = project.properties["version"]?.toString()
val buildNumber = project.properties["buildNumber"]?.toString()

// Set the version based on the available information
if (providedVersion != null && providedVersion != "unspecified" && providedVersion != "1.0.0-SNAPSHOT") {
    version = providedVersion
} else if (buildNumber != null && buildNumber.isNotEmpty()) {
    version = "1.0.$buildNumber"
} else {
    version = "1.0.0-SNAPSHOT"
}

// If a specific group is provided, use that
val providedGroup = project.properties["group"]?.toString()
if (providedGroup != null && providedGroup.isNotEmpty()) {
    group = providedGroup
}

// Check for publishGroupId which will be used for Maven publications
val publishGroupId = project.properties["publishGroupId"]?.toString() ?: group.toString()

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.allopen)
    `java-library`
    `maven-publish`
}

// Apply a specific Java toolchain to ease working on different environments.
java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
    withJavadocJar()
    withSourcesJar()
}

// Configure Kotlin to target JVM 21
kotlin {
    jvmToolchain(21)

    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}

dependencies {
    // Quarkus BOM - use same version as parent project
    val quarkusVersion = "3.22.2"

    // Quarkus core dependencies (API scope for consuming projects)
    api("io.quarkus:quarkus-core:$quarkusVersion")
    api("io.quarkus:quarkus-hibernate-orm-panache-kotlin:$quarkusVersion")
    api("io.quarkus:quarkus-smallrye-jwt:$quarkusVersion")
    api("io.quarkus:quarkus-smallrye-openapi:$quarkusVersion")
    api("io.quarkus:quarkus-rest-jackson:$quarkusVersion")
    api("io.quarkus:quarkus-arc:$quarkusVersion")
    api("io.quarkus:quarkus-hibernate-validator:$quarkusVersion")
    api("io.quarkus:quarkus-vertx:$quarkusVersion")

    // Additional libs using version catalog
    api(libs.ulid)
    api(libs.java.jwt)
    api("com.bucket4j:bucket4j-core:8.7.0")
    api("at.favre.lib:bcrypt:0.10.2")
    api("commons-codec:commons-codec:1.16.0")

    // Incept5 external dependencies
    api(libs.incept5.correlation)
    api(libs.incept5.error.quarkus)

    // JSON processing
    api("com.fasterxml.jackson.core:jackson-databind")
    api("com.fasterxml.jackson.module:jackson-module-kotlin")
    api("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")

    // Logbook dependencies
    implementation(enforcedPlatform(libs.logbook.bom))
    api(libs.logbook.core)
    api(libs.logbook.jaxrs)

    // Spring WebClient for HTTP calls
    api(libs.spring.webflux)
    api(libs.spring.context)
    api(libs.reactor.netty)

    // Jandex for CDI bean discovery
    implementation("io.smallrye:jandex:3.1.2")

    // Testing dependencies
    testImplementation("io.quarkus:quarkus-junit5:$quarkusVersion")
    testImplementation("io.rest-assured:rest-assured:5.4.0")
    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.kotest.runner.junit5)
    testImplementation(libs.kotest.assertions.core)
    testImplementation(libs.wiremock)
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.1")
    testImplementation("org.assertj:assertj-core:3.24.2")
    testImplementation("ch.qos.logback:logback-classic:1.4.14")
}

// All-open annotations for Quarkus
allOpen {
    annotation("jakarta.enterprise.context.ApplicationScoped")
    annotation("jakarta.enterprise.context.RequestScoped")
    annotation("jakarta.ws.rs.ext.Provider")
    annotation("jakarta.ws.rs.Path")
    annotation("jakarta.persistence.Entity")
    annotation("io.quarkus.test.junit.QuarkusTest")
}

tasks.withType<Test> {
    useJUnitPlatform()
    systemProperty("java.util.logging.manager", "org.jboss.logmanager.LogManager")
}

// Generate Jandex index for Quarkus CDI discovery
tasks.register<JavaExec>("jandex") {
    group = "build"
    description = "Generate Jandex index for CDI bean discovery"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("org.jboss.jandex.Main")
    val indexFile = layout.buildDirectory.file("resources/main/META-INF/jandex.idx").get().asFile
    doFirst {
        indexFile.parentFile.mkdirs()
    }
    args(
        "-o", indexFile.absolutePath,
        layout.buildDirectory.dir("classes/kotlin/main").get().asFile.absolutePath
    )
    dependsOn(tasks.classes)
    outputs.file(indexFile)
}

tasks.jar {
    dependsOn(tasks.named("jandex"))
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    from(layout.buildDirectory.file("resources/main/META-INF/jandex.idx")) {
        into("META-INF")
    }
    // Ensure beans.xml is included
    from(sourceSets["main"].resources) {
        include("META-INF/beans.xml")
    }
}

// Configure publishing for JitPack
publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            
            // For JitPack compatibility, we need to use the correct group ID format
            val jitpackGroupId = if (System.getenv("JITPACK") != null) {
                // When building on JitPack
                "com.github.incept5"
            } else {
                // For local development
                publishGroupId
            }

            groupId = jitpackGroupId
            artifactId = "platform-core-lib"
            version = project.version.toString()

            // Add POM information
            pom {
                name.set("Platform Core Library")
                description.set("Core platform utilities and components for Quarkus applications")
                url.set("https://github.com/incept5/platform-core-lib")

                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }

                developers {
                    developer {
                        id.set("incept5")
                        name.set("Incept5")
                        email.set("info@incept5.com")
                    }
                }

                scm {
                    connection.set("scm:git:github.com/incept5/platform-core-lib.git")
                    developerConnection.set("scm:git:ssh://github.com/incept5/platform-core-lib.git")
                    url.set("https://github.com/incept5/platform-core-lib/tree/main")
                }
            }
        }
    }

    repositories {
        mavenLocal()
    }
}

// Suppress enforced platform validation for publishing
tasks.withType<GenerateModuleMetadata> {
    suppressedValidationErrors.add("enforced-platform")
}
