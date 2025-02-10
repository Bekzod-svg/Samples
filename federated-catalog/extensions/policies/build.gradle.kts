plugins {
    `java-library`
}

dependencies {
    api(libs.edc.spi.contract)
    api(libs.edc.core.spi)
    api(libs.edc.spi.policy.engine)
    implementation(libs.ih.spi.core)
    implementation(project(":federated-catalog:extensions:trusted-participants-whitelist"))
    testImplementation(libs.edc.core.policy.engine)
    implementation(libs.ih.spi.identityhub)
//    implementation(libs.edc.spi.core)
//    implementation(libs.edc.contract.spi)
    implementation(libs.edc.connector.spi)
}
