// [C] Bentosmau-gif - Dev 26/ all rights reserved.
#include <iostream>
#include <iomanip>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

AntiVirus::AntiVirus() : scanner(), heuristic(), signatures() {
}

AntiVirus::~AntiVirus() {
}

void AntiVirus::initialize() {
    std::cout << "\n╔════════════════════════════════════╗\n";
    std::cout << "║    Carl Power Anti-Malware       ║\n";
    std::cout << "║  Real-time Malware Detection       ║\n";
    std::cout << "╚════════════════════════════════════╝\n\n";
    
    std::cout << "[*] Initializing antivirus modules...\n";
    std::cout << "[+] Scanner module ready\n";
    std::cout << "[+] Heuristic analyzer ready\n";
    std::cout << "[+] Signature database ready\n";
    std::cout << "[*] Antivirus engine initialized successfully\n\n";
}

void AntiVirus::performFullAnalysis(ScanResult& result) {
    std::ifstream file(result.filePath, std::ios::binary);
    if (!file.is_open()) {
        return;
    }
    
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    
    // Check signatures first
    if (signatures.matchesSignature(content, result.filePath)) {
        result.threatLevel = ThreatLevel::MALWARE;
        result.detectionName = signatures.getMatchedSignatureName();
        result.details = "Signature match detected";
        return;
    }
    
    // If not matched by signature, use heuristic analysis
    ThreatLevel heuristicLevel = heuristic.analyzeBehavior(content);
    if (heuristicLevel > result.threatLevel) {
        result.threatLevel = heuristicLevel;
        if (result.threatLevel == ThreatLevel::MALWARE) {
            result.detectionName = "Heuristic.Malware";
        } else if (result.threatLevel == ThreatLevel::SUSPICIOUS) {
            result.detectionName = "Heuristic.Suspicious";
        }
        result.details = "Heuristic analysis flagged as potential threat";
    }
}

void AntiVirus::scanTarget(const std::string& targetPath) {
    std::cout << "[*] Starting scan on: " << targetPath << "\n\n";
    
    if (fs::is_regular_file(targetPath)) {
        std::cout << "[>] Scanning file...\n";
        ScanResult result = scanner.scanFile(targetPath);
        performFullAnalysis(result);
        results.push_back(result);
    } else if (fs::is_directory(targetPath)) {
        std::cout << "[>] Scanning directory recursively...\n";
        std::vector<ScanResult> dirResults = scanner.scanDirectory(targetPath);
        for (auto& result : dirResults) {
            performFullAnalysis(result);
            results.push_back(result);
        }
    } else {
        std::cout << "[!] Invalid target path\n";
        return;
    }
    
    std::cout << "\n[+] Scan complete\n\n";
}

void AntiVirus::printScanResult(const ScanResult& result) {
    std::string threatStr;
    std::string threatIcon;
    
    switch (result.threatLevel) {
        case ThreatLevel::CLEAN:
            threatStr = "CLEAN";
            threatIcon = "✓";
            break;
        case ThreatLevel::SUSPICIOUS:
            threatStr = "SUSPICIOUS";
            threatIcon = "⚠";
            break;
        case ThreatLevel::MALWARE:
            threatStr = "MALWARE";
            threatIcon = "✗";
            break;
    }
    
    std::cout << "[" << threatIcon << "] " << std::left << std::setw(30) << result.filePath 
              << " | " << std::setw(15) << threatStr;
    
    if (!result.detectionName.empty()) {
        std::cout << " | " << result.detectionName;
    }
    std::cout << "\n";
    
    if (!result.details.empty()) {
        std::cout << "    └─ " << result.details << "\n";
    }
}

void AntiVirus::printResults() {
    std::cout << "╔════════════════════════════════════╗\n";
    std::cout << "║        SCAN RESULTS                ║\n";
    std::cout << "╚════════════════════════════════════╝\n\n";
    
    int cleanCount = 0, suspiciousCount = 0, malwareCount = 0;
    
    for (const auto& result : results) {
        printScanResult(result);
        
        if (result.threatLevel == ThreatLevel::CLEAN) cleanCount++;
        else if (result.threatLevel == ThreatLevel::SUSPICIOUS) suspiciousCount++;
        else if (result.threatLevel == ThreatLevel::MALWARE) malwareCount++;
    }
    
    std::cout << "\n╔════════════════════════════════════╗\n";
    std::cout << "║        SUMMARY                     ║\n";
    std::cout << "╚════════════════════════════════════╝\n";
    std::cout << "Total Files: " << results.size() << "\n";
    std::cout << "Clean:       " << cleanCount << "\n";
    std::cout << "Suspicious:  " << suspiciousCount << "\n";
    std::cout << "Malware:     " << malwareCount << "\n";
    std::cout << "\n";
}
