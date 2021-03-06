import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

group = "com.tyro.techtalk"
version = "1.0-SNAPSHOT"

buildscript {
    var kotlin_version: String by extra
    kotlin_version = "1.1.61"

    repositories {
        mavenCentral()
    }
    
    dependencies {
        classpath(kotlinModule("gradle-plugin", kotlin_version))
    }
    
}

apply {
    plugin("kotlin")
}

val kotlin_version: String by extra

repositories {
    mavenCentral()
    jcenter()
}

dependencies {
    compile(kotlinModule("stdlib-jre8", kotlin_version))
    compile("com.github.h0tk3y.betterParse:better-parse:0.3.1")
    testCompile("io.kotlintest:kotlintest:2.0.7")
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}