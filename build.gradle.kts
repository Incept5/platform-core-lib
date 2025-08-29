
plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.allopen)
    `java-library`
}

group = "org.incept5.platform"
version = "1.0.0-SNAPSHOT"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
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
    api(libs.incept5.cryptography)

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
