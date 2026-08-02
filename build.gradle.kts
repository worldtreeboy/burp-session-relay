plugins {
    java
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.2")
    implementation("com.google.code.gson:gson:2.11.0")
    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks.test { useJUnitPlatform() }

tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.shadowJar {
    archiveBaseName.set("burp-session-relay")
    archiveClassifier.set("")
    archiveVersion.set("")
}
