package com.cybershield.model;

import java.util.ArrayList;
import java.util.List;

public class MlPredictionResult {
    private String prediction; // "PHISHING" or "LEGITIMATE"
    private double probability; // 0.0 to 1.0 (phishing probability)
    private double confidencePercentage; // 0.0 to 100.0
    private String modelName;
    private List<String> topContributingFeatures = new ArrayList<>();
    private double riskScoreContribution;

    public MlPredictionResult() {
    }

    public MlPredictionResult(String prediction, double probability, double confidencePercentage,
                              String modelName, List<String> topContributingFeatures,
                              double riskScoreContribution) {
        this.prediction = prediction;
        this.probability = probability;
        this.confidencePercentage = confidencePercentage;
        this.modelName = modelName;
        this.topContributingFeatures = topContributingFeatures != null ? topContributingFeatures : new ArrayList<>();
        this.riskScoreContribution = riskScoreContribution;
    }

    public String getPrediction() {
        return prediction;
    }

    public void setPrediction(String prediction) {
        this.prediction = prediction;
    }

    public double getProbability() {
        return probability;
    }

    public void setProbability(double probability) {
        this.probability = probability;
    }

    public double getConfidencePercentage() {
        return confidencePercentage;
    }

    public void setConfidencePercentage(double confidencePercentage) {
        this.confidencePercentage = confidencePercentage;
    }

    public String getModelName() {
        return modelName;
    }

    public void setModelName(String modelName) {
        this.modelName = modelName;
    }

    public List<String> getTopContributingFeatures() {
        return topContributingFeatures;
    }

    public void setTopContributingFeatures(List<String> topContributingFeatures) {
        this.topContributingFeatures = topContributingFeatures;
    }

    public double getRiskScoreContribution() {
        return riskScoreContribution;
    }

    public void setRiskScoreContribution(double riskScoreContribution) {
        this.riskScoreContribution = riskScoreContribution;
    }
}
