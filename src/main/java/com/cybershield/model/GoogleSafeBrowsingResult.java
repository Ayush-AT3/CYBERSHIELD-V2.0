package com.cybershield.model;

public class GoogleSafeBrowsingResult {

    private boolean threatFound;
    private String threatType; // SOCIAL_ENGINEERING, MALWARE, UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION
    private String platformType;
    private String threatUrl;
    private String cacheDuration;
    private boolean simulated;

    public GoogleSafeBrowsingResult() {
    }

    public GoogleSafeBrowsingResult(boolean threatFound, String threatType, String platformType, String threatUrl, boolean simulated) {
        this.threatFound = threatFound;
        this.threatType = threatType;
        this.platformType = platformType;
        this.threatUrl = threatUrl;
        this.simulated = simulated;
    }

    public boolean isThreatFound() {
        return threatFound;
    }

    public void setThreatFound(boolean threatFound) {
        this.threatFound = threatFound;
    }

    public String getThreatType() {
        return threatType;
    }

    public void setThreatType(String threatType) {
        this.threatType = threatType;
    }

    public String getPlatformType() {
        return platformType;
    }

    public void setPlatformType(String platformType) {
        this.platformType = platformType;
    }

    public String getThreatUrl() {
        return threatUrl;
    }

    public void setThreatUrl(String threatUrl) {
        this.threatUrl = threatUrl;
    }

    public String getCacheDuration() {
        return cacheDuration;
    }

    public void setCacheDuration(String cacheDuration) {
        this.cacheDuration = cacheDuration;
    }

    public boolean isSimulated() {
        return simulated;
    }

    public void setSimulated(boolean simulated) {
        this.simulated = simulated;
    }
}
