// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.mtas.LicenseManagement -Wno-everything -verify %s
struct LMFeatureHandler_mod {
    void licenseRequest () {}
};

struct TSPLicenseManagerBackend {
    void requestLicense() {
        LMFeatureHandler_mod m;
        m.licenseRequest();
    }

    void safeRequestLicense() {
        requestLicense();
    }
};

void f () {
    TSPLicenseManagerBackend l;
    l.requestLicense();// expected-warning {{TSPLicenseManagerBackend should be used instead of raw license management}}
    l.safeRequestLicense();
}
