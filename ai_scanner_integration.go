package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
)

// SecurityScanAlert represents an alert from the AI scanner
type SecurityScanAlert struct {
	Severity        string `json:"severity"`
	Type            string `json:"type"`
	Message         string `json:"message"`
	FilePath        string `json:"file_path"`
	PID             string `json:"pid"`
	ClientID        string `json:"client_id"`
	ClientName      string `json:"client_name"`
	Hash            string `json:"hash"`
	Timestamp       string `json:"timestamp"`
	DetectionMethod string `json:"detection_method"`
	AIAnalysis      string `json:"ai_analysis,omitempty"`
}

// RunAIScanner executes the Python AI scanner on collected processes
// Processes should include ClientID field for proper attribution
func RunAIScanner(processes []Process) []SecurityAlert {
	// Create input for scanner
	inputData := map[string]interface{}{
		"processes": processes,
	}

	inputJSON, err := json.Marshal(inputData)
	if err != nil {
		log.Printf("Error marshaling process data: %v", err)
		return []SecurityAlert{}
	}

	// Execute Python scanner with proper environment
	cmd := exec.Command("python", "ai_scanner.py")
	cmd.Dir = "." // Ensure it runs in the project root to find malicious.csv
	cmd.Stdin = bytes.NewReader(inputJSON)
	
	// Inherit system environment (to get OPENAI_API_KEY)
	cmd.Env = os.Environ()

	// Capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error running AI scanner: %v | Output: %s", err, string(output))
		return []SecurityAlert{}
	}

	// Parse scanner output
	var scanAlerts []SecurityScanAlert
	err = json.Unmarshal(output, &scanAlerts)
	if err != nil {
		log.Printf("Error parsing scanner output: %v", err)
		return []SecurityAlert{}
	}

	// Convert to SecurityAlert for dashboard display
	var alerts []SecurityAlert
	for _, scanAlert := range scanAlerts {
		alert := SecurityAlert{
			ID:       fmt.Sprintf("scan_%d_%s", len(alerts), scanAlert.Hash[:8]),
			Time:     scanAlert.Timestamp,
			Severity: scanAlert.Severity,
			Message:  fmt.Sprintf("%s | Client: %s | Method: %s", scanAlert.Message, scanAlert.ClientName, scanAlert.DetectionMethod),
			FilePath: scanAlert.FilePath,
			PID:      scanAlert.PID,
			ClientID: scanAlert.ClientID, // CRITICAL FIX: Propagate ClientID
		}

		// Include extra context if available
		if scanAlert.AIAnalysis != "" {
			alert.Message += fmt.Sprintf(" | Analysis: %s", scanAlert.AIAnalysis)
		}

		alerts = append(alerts, alert)
	}

	return alerts
}

// RunAIScannerAsync runs the scanner asynchronously and triggers automated isolation/reporting
func RunAIScannerAsync(processes []Process, scannedClientIDs []string) {
	go func() {
		alerts := RunAIScanner(processes)
		mu.Lock()
		defer mu.Unlock()
		
		// Use consolidated alert and isolation logic with client tracking
		HandleSecurityAlerts(alerts, scannedClientIDs)
		
		log.Printf("AI Scanner (Background): Found %d threats for clients %v", len(alerts), scannedClientIDs)
	}()
}

// GetClientName retrieves the display name for a client (hostname or ID)
func GetClientName(clientID string) string {
	mu.RLock()
	defer mu.RUnlock()

	// Try to get from client data (if OS/Version is available, use hostname as name)
	if client, ok := clients[clientID]; ok {
		// clientID often contains hostname, extract it
		if client.OS != "" {
			return clientID // Use ID as-is, contains hostname
		}
	}
	return clientID
}

// TagProcessesWithClientID adds clientID to all processes from a specific client
func TagProcessesWithClientID(processes []Process, clientID string) []Process {
	for i := range processes {
		processes[i].ClientID = clientID
	}
	return processes
}

// Example usage in process polling handler:
/*
func processPollHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	// ... existing code ...

	// When you have collected processes:
	if len(processData[id]) > 0 {
		// Tag with client ID
		taggedProcesses := TagProcessesWithClientID(processData[id], id)

		// Run AI scanner asynchronously
		RunAIScannerAsync(taggedProcesses)
	}
}
*/
