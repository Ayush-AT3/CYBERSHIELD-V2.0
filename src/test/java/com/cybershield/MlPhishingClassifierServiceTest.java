package com.cybershield;

import com.cybershield.model.MlPredictionResult;
import com.cybershield.service.ml.MlPhishingClassifierService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class MlPhishingClassifierServiceTest {

    private MlPhishingClassifierService mlService;

    @BeforeEach
    public void setUp() {
        mlService = new MlPhishingClassifierService();
    }

    @Test
    public void testPhishingEmailPrediction() {
        String subject = "URGENT: Your bank account will be suspended immediately";
        String body = "Dear customer, unauthorized access was detected. Verify your login credentials and password within 24 hours to prevent locked security access.";

        MlPredictionResult result = mlService.predictEmail(subject, body);

        assertNotNull(result);
        assertEquals("PHISHING", result.getPrediction());
        assertTrue(result.getProbability() > 0.60, "Phishing probability should exceed 0.60");
        assertTrue(result.getConfidencePercentage() > 60.0, "Confidence should exceed 60%");
        assertTrue(result.getRiskScoreContribution() > 0.0, "Risk score contribution should be positive");
        assertFalse(result.getTopContributingFeatures().isEmpty(), "Should extract influential feature words");
    }

    @Test
    public void testLegitimateEmailPrediction() {
        String subject = "Project meeting notes and schedule";
        String body = "Hi team, please find attached the weekly summary of our software development sprint. Let me know if you have any questions.";

        MlPredictionResult result = mlService.predictEmail(subject, body);

        assertNotNull(result);
        assertEquals("LEGITIMATE", result.getPrediction());
        assertTrue(result.getProbability() < 0.50, "Legitimate email probability should be under 0.50");
        assertEquals(0.0, result.getRiskScoreContribution(), "Legitimate email should contribute 0 risk score");
    }

    @Test
    public void testPhishingUrlPrediction() {
        String maliciousUrl = "http://192.168.1.1/login/verify-account-security.php?token=xyz";

        MlPredictionResult result = mlService.predictUrl(maliciousUrl);

        assertNotNull(result);
        assertEquals("PHISHING", result.getPrediction());
        assertTrue(result.getProbability() > 0.60, "Malicious URL should have high probability");
        assertTrue(result.getTopContributingFeatures().contains("raw_ip_host"));
    }

    @Test
    public void testLegitimateUrlPrediction() {
        String safeUrl = "https://www.google.com/search?q=cybersecurity+defense";

        MlPredictionResult result = mlService.predictUrl(safeUrl);

        assertNotNull(result);
        assertEquals("LEGITIMATE", result.getPrediction());
        assertTrue(result.getProbability() < 0.50);
    }

    @Test
    public void testLegitimateInstagramLoginUrlPrediction() {
        String instaUrl = "https://www.instagram.com/accounts/login/?hl=en";

        MlPredictionResult result = mlService.predictUrl(instaUrl);

        assertNotNull(result);
        assertEquals("LEGITIMATE", result.getPrediction(), "Official Instagram login URL must be classified as LEGITIMATE");
        assertTrue(result.getProbability() < 0.20, "Probability should be very low due to trusted domain reputation");
        assertEquals(0.0, result.getRiskScoreContribution());
        assertTrue(result.getTopContributingFeatures().contains("trusted_domain_reputation"));
    }
}
