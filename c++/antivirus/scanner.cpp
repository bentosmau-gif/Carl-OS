// [C] Bentosmau-gif - Dev 26/ all rights reserved.
#include "scanner.h"
#include <iostream>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

Scanner::Scanner() {
    std::cout << "[Scanner] Initialized\n";
}

Scanner::~Scanner() {
}

bool Scanner::fileExists(const std::string& filePath) {
    return fs::exists(filePath);
}

std::string Scanner::readFileContent(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

ScanResult Scanner::scanFile(const std::string& filePath) {
    ScanResult result;
    result.filePath = filePath;
    result.threatLevel = ThreatLevel::CLEAN;
    result.detectionName = "";
    result.details = "";

    if (!fileExists(filePath)) {
        result.threatLevel = ThreatLevel::SUSPICIOUS;
        result.detectionName = "FILE_NOT_FOUND";
        result.details = "File does not exist";
        return result;
    }

    std::string content = readFileContent(filePath);
    
    // Basic heuristic checks
    if (content.find("eval(") != std::string::npos || 
        content.find("exec(") != std::string::npos) {
        result.threatLevel = ThreatLevel::SUSPICIOUS;
        result.detectionName = "SUSPICIOUS_EVAL_EXEC";
        result.details = "File contains suspicious eval/exec functions";
    }
    
    if (content.find("rm -rf /") != std::string::npos) {
        result.threatLevel = ThreatLevel::MALWARE;
        result.detectionName = "DESTRUCTIVE_COMMAND";
        result.details = "File contains destructive shell commands";
    }

    result.details += " (Size: " + std::to_string(content.size()) + " bytes)";
    return result;
}

std::vector<ScanResult> Scanner::scanDirectory(const std::string& dirPath) {
    std::vector<ScanResult> results;
    
    if (!fileExists(dirPath)) {
        return results;
    }

    for (const auto& entry : fs::recursive_directory_iterator(dirPath)) {
        if (entry.is_regular_file()) {
            results.push_back(scanFile(entry.path().string()));
        }
    }

    return results;
}
