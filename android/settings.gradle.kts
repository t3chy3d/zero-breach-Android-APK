pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
        maven { url = uri("/home/hatch/workspace/goals/build-pinpoint-android-app/app/local-repo") }
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url = uri("/home/hatch/workspace/goals/build-pinpoint-android-app/app/local-repo") }
    }
}
rootProject.name = "ZeroBreach"
include(":app")
