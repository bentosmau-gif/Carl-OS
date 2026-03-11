#include "heuristic.h"
#include <iostream>
#include <sstream>

HeuristicAnalyzer::HeuristicAnalyzer() {
    std::cout << "[HeuristicAnalyzer] Initialized\n";
}

HeuristicAnalyzer::~HeuristicAnalyzer() {
}

bool HeuristicAnalyzer::hasNetworkBehavior(const std::string& content) {
    return content.find("socket") != std::string::npos ||
           content.find("connect") != std::string::npos ||
           content.find("http://") != std::string::npos ||
           content.find("https://") != std::string::npos;
}

bool HeuristicAnalyzer::hasFileSystemBehavior(const std::string& content) {
    return content.find("unlink") != std::string::npos ||
           content.find("rmdir") != std::string::npos ||
           content.find("fopen") != std::string::npos ||
           content.find("WriteFile") != std::string::npos;
}

bool HeuristicAnalyzer::hasRegistryBehavior(const std::string& content) {
    return content.find("RegOpenKey") != std::string::npos ||
           content.find("RegSetValue") != std::string::npos ||
           content.find("HKEY_") != std::string::npos;
}

bool HeuristicAnalyzer::hasEncryptionBehavior(const std::string& content) {
    return content.find("AES") != std::string::npos ||
           content.find("RSA") != std::string::npos ||
           content.find("encrypt") != std::string::npos ||
           content.find("cipher") != std::string::npos;
}

int HeuristicAnalyzer::calculateRiskScore(const std::string& content) {
    int score = 0;
    
    // More conservative scoring - only if multiple suspicious behaviors present
    int suspiciousCount = 0;
    
    if (hasNetworkBehavior(content)) suspiciousCount++;
    if (hasFileSystemBehavior(content)) suspiciousCount++;
    if (hasRegistryBehavior(content)) suspiciousCount++;
    if (hasEncryptionBehavior(content)) suspiciousCount++;
    
    // Only flag as suspicious if multiple behaviors detected
    if (suspiciousCount >= 2) score += 40;
    else if (suspiciousCount == 1) score += 15;
    
    // Check for obfuscation - much higher threshold
    int nonAlphaNumCount = 0;
    for (char c : content) {
        if (!std::isalnum(c) && !std::isspace(c)) {
            nonAlphaNumCount++;
        }
    }
    if (nonAlphaNumCount > content.size() * 0.65) {
        score += 10;
    }
    
    return score;
}

ThreatLevel HeuristicAnalyzer::analyzeBehavior(const std::string& content) {
    int score = calculateRiskScore(content);
    
    if (score > 60) return ThreatLevel::MALWARE;
    if (score > 30) return ThreatLevel::SUSPICIOUS;
    return ThreatLevel::CLEAN;
}

std::string HeuristicAnalyzer::generateRiskReport(const std::vector<ScanResult>& results) {
    std::ostringstream report;
    
    int cleanCount = 0, suspiciousCount = 0, malwareCount = 0;
    
    for (const auto& result : results) {
        if (result.threatLevel == ThreatLevel::CLEAN) cleanCount++;
        else if (result.threatLevel == ThreatLevel::SUSPICIOUS) suspiciousCount++;
        else if (result.threatLevel == ThreatLevel::MALWARE) malwareCount++;
    }
    
    report << "\n===== HEURISTIC ANALYSIS REPORT =====\n";
    report << "Total Files Scanned: " << results.size() << "\n";
    report << "Clean: " << cleanCount << "\n";
    report << "Suspicious: " << suspiciousCount << "\n";
    report << "Malware: " << malwareCount << "\n";
    report << "=====================================\n";
    
    return report.str();
}

// [C] bentosmau-gif - Dev 26/ All rights reserved
