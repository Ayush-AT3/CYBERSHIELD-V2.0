package com.cybershield.model;

public class GeminiAnalysisResult {

    private String verdict; // PHISHING, SUSPICIOUS, SAFE
    private String reasoning; // 2-3 sentence Explainable AI synthesis
    private String primaryTactic; // e.g. AUTHORITY_IMPERSONATION, URGENT_CREDENTIAL_HARVESTING, FINANCIAL_EXTORTION, BENIGN
    private double confidenceScore; // 0.0 to 1.0
    private boolean simulated;

    public GeminiAnalysisResult() {
    }

    public GeminiAnalysisResult(String verdict, String reasoning, String primaryTactic, double confidenceScore, boolean simulated) {
        this.verdict = verdict;
        this.reasoning = reasoning;
        this.primaryTactic = primaryTactic;
        this.confidenceScore = confidenceScore;
        this.simulated = simulated;
    }

    public String getVerdict() {
        return verdict;
    }

    public void setVerdict(String verdict) {
        this.verdict = verdict;
    }

    public String getReasoning() {
        return reasoning;
    }

    public void setReasoning(String reasoning) {
        this.reasoning = reasoning;
    }

    public String getPrimaryTactic() {
        return primaryTactic;
    }

    public void setPrimaryTactic(String primaryTactic) {
        this.primaryTactic = primaryTactic;
    }

    public double getConfidenceScore() {
        return confidenceScore;
    }

    public void setConfidenceScore(double confidenceScore) {
        this.confidenceScore = confidenceScore;
    }

    public boolean isSimulated() {
        return simulated;
    }

    public void setSimulated(boolean simulated) {
        this.simulated = simulated;
    }
}
