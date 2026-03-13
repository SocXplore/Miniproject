package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"
)

// ... (existing constants)
const (
	username      = "admin"
	password      = "malwarekid"
	sessionCookie = "isolax-session"
	listenAddr    = ":8080"
	timeout       = 10 * time.Second
)

// ... (existing structs)
type Client struct {
	Frame     []byte
	Timestamp time.Time
	OS        string
	Version   string
	Hostname  string // Added Hostname
}

type ShellCommand struct {
	Command string
}

type ShellResponse struct {
	Output string
}

type KillRequest struct {
	PID int `json:"pid"`
}

type FileInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	ModTime string `json:"mod_time"`
	Path    string `json:"path"`
}

type FileRequest struct {
	Action string `json:"action"`
	Path   string `json:"path"`
}

type EDRCommand struct {
	Type string `json:"type"` // "isolate" or "unisolate"
}

type SecurityAlert struct {
	ID       string
	Time     string
	Severity string // "High", "Medium", "Low"
	Message  string
	FilePath string
	PID      string
	ClientID string // Added ClientID
}

type Process struct {
	PID            int    `json:"pid"`
	Name           string `json:"name"`
	ExecutablePath string `json:"executable_path"`
	CommandLine    string `json:"command_line"`
	Hash           string `json:"hash"`
	ClientID       string `json:"client_id,omitempty"` // Added for scanner
}

type Service struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	StartType   string `json:"start_type"`
	PathName    string `json:"path_name"`
	Hash        string `json:"hash"`
}

type ClientView struct {
	ID        string
	OS        string
	Version   string
	Status    string
	Isolation string
	History   []string // NEW
}

var (
	mu              sync.RWMutex
	clients         = make(map[string]*Client)
	commands        = make(map[string]string)
	responses       = make(map[string]string)
	commandHistory  = make(map[string]string)
	processCommands = make(map[string]string) // NEW: Queue for process commands
	serviceCommands = make(map[string]string) // Queue for service commands
	stopCommands    = make(map[string]string) // Queue for stop service commands
	startCommands   = make(map[string]string) // Queue for start service commands
	fileCommands    = make(map[string]FileRequest)
	fileResponses   = make(map[string][]FileInfo)
	processData     = make(map[string][]Process)
	serviceData     = make(map[string][]Service)
	edrCommands     = make(map[string]string) // clientID -> "isolate" / "unisolate"

	// Mock alerts for demonstration (now used for real alerts too)
	mockAlerts = []SecurityAlert{}

	// NEW: isolation state + history
	isolationState = make(map[string]string)   // clientID -> "Normal"/"Isolated"
	isolationLog   = make(map[string][]string) // clientID -> []history lines
)

//go:embed templates/*
var templates embed.FS

// ... (existing helper functions)
func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	return cookie.Value == "valid-session"
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, err := template.ParseFS(templates, "templates/login.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
		return
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		user := r.FormValue("username")
		pass := r.FormValue("password")

		if user == username && pass == password {
			http.SetCookie(w, &http.Cookie{
				Name:  sessionCookie,
				Value: "valid-session",
				Path:  "/",
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/login?error=Invalid credentials", http.StatusSeeOther)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookie,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	mu.RLock()
	// Create a slice of client IDs or client info
	var clientsData []ClientView
	for id, client := range clients {
		isoStatus := "Normal"
		if val, ok := isolationState[id]; ok {
			isoStatus = val
		}

		status := "offline"
		if time.Since(client.Timestamp) < 30*time.Second {
			status = "online"
		}

		clientsData = append(clientsData, ClientView{
			ID:        id,
			OS:        client.OS,
			Version:   client.Version,
			Status:    status,
			Isolation: isoStatus,
		})
	}

	data := map[string]interface{}{
		"Clients": clientsData,
		"Alerts":  mockAlerts,
	}
	mu.RUnlock()

	tmpl, err := template.ParseFS(templates, "templates/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

func notificationsHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	mu.RLock()
	var clientsData []ClientView
	for id, client := range clients {
		isoStatus := "Normal"
		if val, ok := isolationState[id]; ok {
			isoStatus = val
		}

		status := "offline"
		if time.Since(client.Timestamp) < 30*time.Second {
			status = "online"
		}

		clientsData = append(clientsData, ClientView{
			ID:        id,
			OS:        client.OS,
			Version:   client.Version,
			Status:    status,
			Isolation: isoStatus,
		})
	}

	// Simply pass the global mockAlerts
	data := map[string]interface{}{
		"Clients": clientsData,
		"Alerts":  mockAlerts,
	}
	mu.RUnlock()

	tmpl, err := template.ParseFS(templates, "templates/notifications.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

func clientHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing client ID", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusInternalServerError)
		return
	}

	clients[id] = &Client{
		Frame:     body,
		Timestamp: time.Now(),
		OS:        r.Header.Get("X-Client-OS"),
		Version:   r.Header.Get("X-Client-Ver"),
		Hostname:  r.Header.Get("X-Client-Hostname"), // Capture Hostname
	}

	// Check for pending isolation commands
	if cmd, ok := edrCommands[id]; ok {
		// Send command in response header or body?
		// For simplicity, let's use a custom header "X-EDR-Command"
		// The client needs to check this.
		// Assuming previous logic used polling or similar.
		// We'll leave it as is for now or adapt if client polls.
		// This handler handles frame uploads.
		_ = cmd
	}

	w.WriteHeader(http.StatusOK)
}

func commandHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodPost {
		id := r.URL.Query().Get("id")
		if id == "" {
			id = r.FormValue("id")
		}
		cmd := r.FormValue("command")

		mu.Lock()
		commands[id] = cmd
		mu.Unlock()

		// If it's an AJAX request (no redirect wanted), just return OK
		// Check for some header or just assume standard behavior if redirecting?
		// The new Shell.html uses fetch. Fetch follows redirects by default or we can just return 200.
		// Let's just return 200 OK text so fetch works.
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Command queued")
		return
	}
}

func pollCommandHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.Lock()
	cmd, ok := commands[id]
	if ok {
		delete(commands, id)
	}
	mu.Unlock()

	// Removed extra unlock
	if ok {
		// client.go expects JSON: {"Command": "..."}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"Command": cmd})
	}
}

func responseHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	body, _ := ioutil.ReadAll(r.Body)

	mu.Lock()
	responses[id] = string(body)
	commandHistory[id] += fmt.Sprintf("$ %s\n> %s\n", "Previous Command", string(body)) // Simplified history
	mu.Unlock()
}

func terminalHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	id := r.URL.Query().Get("id")
	mu.RLock()
	history := commandHistory[id]
	mu.RUnlock()

	tmpl, err := template.ParseFS(templates, "templates/shell.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, struct{ ClientID, History string }{id, history})
}

// Handler for AJAX terminal updates
func terminalUpdatesHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.RLock()
	// In a real app we'd track last read offset.
	// Here we just return the full history or last chunk?
	// Let's just return the last response for now or empty if none?
	// Actually, `commandHistory` grows. Let's simplistically return the whole thing?
	// Or better: The client JS can't handle diffing easily.
	// Let's just return the last "response" set by client?
	// No, `commandHistory` is safer.

	// Simplification: We add a 'last_len' param to query?
	// For this MVP, let's just return nothing and rely on manual reload if needed?
	// The user wants it to Work.

	// Strategy: Return the *latest* response that was received.
	val := responses[id]

	// Clear it so we don't resend repeats forever
	if val != "" {
		responses[id] = ""
	}
	mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"new_output": val,
	})
}

// Handler for rendering processes.html
func processHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		// Just show list of clients to select?
		// For now simple alert
		http.Error(w, "Client ID required", http.StatusBadRequest)
		return
	}

	// Trigger process list request
	// Trigger process list request
	mu.Lock()
	processCommands[id] = "list" // Queue specific "list" command for procPoller
	// commands[id] = "ps" // Removed incorrect shell command queueing

	data := processData[id]
	mu.Unlock()

	tmpl, err := template.ParseFS(templates, "templates/processes.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a wrapper struct for the template
	pageData := struct {
		ClientID  string
		Processes []Process
	}{
		ClientID:  id,
		Processes: data,
	}

	tmpl.Execute(w, pageData)
}

// Handler to receive process data from client
func procPollHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.Lock()
	cmd, ok := processCommands[id]
	if ok {
		delete(processCommands, id)
	}
	mu.Unlock()

	if ok {
		// client.go expects JSON: {"command": "list"}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"command": "%s"}`, cmd)
	}
}

func processResultHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	body, _ := ioutil.ReadAll(r.Body)

	var payload struct {
		Processes []Process `json:"processes"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		// Fallback for old pipe format if needed, but we moved to JSON
		log.Printf("Error decoding process JSON: %v", err)
		return
	}

	mu.Lock()
	processData[id] = payload.Processes
	mu.Unlock()

	// NEW: Run AI Scanner on processes asynchronously
	if len(payload.Processes) > 0 {
		// Tag processes with client ID
		for i := range payload.Processes {
			payload.Processes[i].ClientID = id
		}
		// Run scanner asynchronously with current client tracking
		RunAIScannerAsync(payload.Processes, []string{id})
	}
}

// File Explorer Handlers
func fileExplorerHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	id := r.URL.Query().Get("id")
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "C:\\" // Default start path
	}

	// Queue command to get file list
	mu.Lock()
	fileCommands[id] = FileRequest{Action: "list", Path: path}
	mu.Unlock()

	// Wait for response (short poll hack for demo)
	time.Sleep(1 * time.Second)

	mu.RLock()
	files := fileResponses[id]
	_ = files // Suppress unused code error
	mu.RUnlock()

	// Define funcMap for formatSize
	funcMap := template.FuncMap{
		"formatSize": func(b int64) string {
			const unit = 1024
			if b < unit {
				return fmt.Sprintf("%d B", b)
			}
			div, exp := int64(unit), 0
			for n := b / unit; n >= unit; n /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
		},
	}

	tmpl, err := template.New("files.html").Funcs(funcMap).ParseFS(templates, "templates/files.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		ClientID    string
		CurrentPath string
		Files       []FileInfo
	}{
		ClientID:    id,
		CurrentPath: path,
		Files:       files,
	}

	tmpl.Execute(w, data)
}

func filePollHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.Lock()
	cmd, ok := fileCommands[id]
	if ok {
		delete(fileCommands, id)
	}
	mu.Unlock()

	if ok {
		json.NewEncoder(w).Encode(cmd)
	}
}

func fileResultHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	body, _ := ioutil.ReadAll(r.Body)

	var files []FileInfo
	json.Unmarshal(body, &files)

	mu.Lock()
	fileResponses[id] = files
	mu.Unlock()
}

// Services Handler
func servicesHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Client ID required", http.StatusBadRequest)
		return
	}

	// Handle POST requests for stop/start service action
	if r.Method == "POST" {
		action := r.FormValue("action")
		serviceName := r.FormValue("service")

		if serviceName != "" {
			if action == "stop" {
				mu.Lock()
				stopCommands[id] = serviceName
				mu.Unlock()
				log.Printf("Queued stop command for service %s on client %s", serviceName, id)
			} else if action == "start" {
				mu.Lock()
				startCommands[id] = serviceName
				mu.Unlock()
				log.Printf("Queued start command for service %s on client %s", serviceName, id)
			}
		}

		// Redirect back to services page
		http.Redirect(w, r, "/services?id="+id, http.StatusSeeOther)
		return
	}

	// Trigger service list request
	mu.Lock()
	serviceCommands[id] = "list"
	data := serviceData[id]
	mu.Unlock()

	log.Printf("servicesHandler: Queued 'list' command for client %s. Currently have %d services in cache.", id, len(data))

	tmpl, err := template.ParseFS(templates, "templates/services.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pageData := struct {
		ClientID string
		Services []Service
	}{
		ClientID: id,
		Services: data,
	}

	tmpl.Execute(w, pageData)
}

// Handler to receive service poll requests from client
func svcPollHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.Lock()
	cmd, ok := serviceCommands[id]
	if ok {
		delete(serviceCommands, id)
	}
	mu.Unlock()

	if ok {
		log.Printf("svcPollHandler: Sending 'list' command to client %s", id)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"command": "%s"}`, cmd)
	} else {
		log.Printf("svcPollHandler: No pending command for client %s", id)
	}
}

// Handler to receive service data from client
func svcResultHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	body, _ := ioutil.ReadAll(r.Body)

	if len(body) == 0 {
		log.Printf("ERROR: svcResultHandler received empty body from client %s", id)
		return
	}

	var payload struct {
		Services []Service `json:"services"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("ERROR decoding service JSON from client %s: %v | Raw body: %s", id, err, string(body))
		return
	}

	if len(payload.Services) == 0 {
		log.Printf("WARNING: Received 0 services from client %s (body was not empty)", id)
	}

	mu.Lock()
	serviceData[id] = payload.Services
	mu.Unlock()

	log.Printf("Received %d services from client %s", len(payload.Services), id)
}

// Handler for service stop polls from client
func svcStopPollHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.Lock()
	cmd, ok := stopCommands[id]
	if ok {
		delete(stopCommands, id)
	}
	mu.Unlock()

	if ok {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"service": "%s"}`, cmd)
	}
}

// Handler for service start polls from client
func svcStartPollHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.Lock()
	cmd, ok := startCommands[id]
	if ok {
		delete(startCommands, id)
	}
	mu.Unlock()

	if ok {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"service": "%s"}`, cmd)
	}
}

// Render "process_paths.html"
func processPathsHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	id := r.URL.Query().Get("id")

	mu.RLock()
	data := processData[id]
	mu.RUnlock()

	tmpl, err := template.ParseFS(templates, "templates/process_paths.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, data)
}

// -- EDR / Isolation Handlers --

func isolationHandler(w http.ResponseWriter, r *http.Request) {
	// API to toggle isolation
	// ?id=CLIENT_ID&action=isolate|unisolate
	id := r.URL.Query().Get("id")
	action := r.URL.Query().Get("action") // "isolate" or "unisolate"

	if id == "" || (action != "isolate" && action != "unisolate") {
		http.Error(w, "Invalid parameters", http.StatusBadRequest)
		return
	}

	mu.Lock()
	edrCommands[id] = action
	status := "Normal"
	if action == "isolate" {
		status = "Isolated"
	}
	isolationState[id] = status

	// Log entry
	logMsg := fmt.Sprintf("[%s] Action: %s | User: %s", time.Now().Format("15:04:05"), action, username)
	isolationLog[id] = append(isolationLog[id], logMsg)
	mu.Unlock()

	// Return JSON success
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "ok", "new_state": "%s"}`, status)
}

func edrPollHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	mu.Lock()
	cmd, ok := edrCommands[id]
	// We might want to keep the state persistent, so maybe don't delete immediately?
	// But command queue is usually consumable.
	// If client polls every 5s, we send it once.
	if ok {
		delete(edrCommands, id)
	}
	mu.Unlock()

	if ok {
		// Output raw command string or JSON
		// Client expects: just the string or json?
		// Let's stick to JSON as defined in struct EDRCommand
		json.NewEncoder(w).Encode(EDRCommand{Type: cmd})
	}
}

// -- AI SCANNER HANDLER --
func HandleSecurityAlerts(newAlerts []SecurityAlert, scannedIDs []string) {
	// Consolidate isolation logic and report generation
	// mu must be locked before calling this

	// Track which clients in THIS scan have threats
	clientsWithThreats := make(map[string]bool)

	for _, alert := range newAlerts {
		if alert.ClientID != "" {
			clientsWithThreats[alert.ClientID] = true
		}

		// AUTOMATED ISOLATION LOGIC
		if alert.Severity == "Critical" || alert.Severity == "High" || alert.Severity == "Medium" {
			clientID := alert.ClientID
			if clientID == "" {
				log.Printf("WARNING: Threat detected but ClientID is missing! Cannot isolate.")
			} else if isolationState[clientID] != "Isolated" {
				isolationState[clientID] = "Isolated"
				edrCommands[clientID] = "isolate"

				logEntry := fmt.Sprintf("[%s] System Isolated due to threat discovery: %s", time.Now().Format("15:04:05"), alert.Message)
				isolationLog[clientID] = append(isolationLog[clientID], logEntry)

				log.Printf("AUTOMATED ISOLATION TRIGGERED for client %s", clientID)
				alert.Message += " | System Isolated successfully."
			}
		}

		mockAlerts = append(mockAlerts, alert)
	}

	// Generate Safe Reports for clean clients that were part of this scan
	for _, clientID := range scannedIDs {
		if !clientsWithThreats[clientID] {
			client, exists := clients[clientID]
			displayName := clientID
			if exists && client.Hostname != "" {
				displayName = client.Hostname
			}

			safeID := clientID
			if len(safeID) > 4 {
				safeID = safeID[:4]
			}
			safeAlert := SecurityAlert{
				ID:       fmt.Sprintf("safe_%d_%s", time.Now().UnixNano(), safeID),
				Time:     time.Now().Format("15:04:05"),
				Severity: "Low",
				Message:  fmt.Sprintf("Scan Complete: %s is safe. No active threats detected.", displayName),
				FilePath: "N/A",
				PID:      "N/A",
				ClientID: clientID,
			}
			mockAlerts = append(mockAlerts, safeAlert)
		}
	}
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Trigger process list AND service list update for ALL clients
	mu.Lock()
	for id := range clients {
		processCommands[id] = "list"
		serviceCommands[id] = "list"
	}
	mu.Unlock()

	// Wait for clients to report back
	time.Sleep(4 * time.Second)

	// 2. Gather all processes and services from all clients
	mu.RLock()
	allProcs := make([]Process, 0)

	for cid, procs := range processData {
		for _, p := range procs {
			p.ClientID = cid
			allProcs = append(allProcs, p)
		}
	}

	for cid, services := range serviceData {
		for _, s := range services {
			svcProc := Process{
				PID:            0,
				Name:           "[SERVICE] " + s.Name,
				ExecutablePath: s.PathName,
				CommandLine:    s.DisplayName,
				Hash:           s.Hash,
				ClientID:       cid,
			}
			allProcs = append(allProcs, svcProc)
		}
	}
	mu.RUnlock()

	// 3. Run integrated scanner (consolidated logic)
	// 3. Run integrated scanner
	scanAlerts := RunAIScanner(allProcs)

	// Collect all scanned IDs for reporting
	scannedIDs := make([]string, 0)
	mu.RLock()
	for id := range clients {
		scannedIDs = append(scannedIDs, id)
	}
	mu.RUnlock()

	// 4. Handle Alerts and Automation
	mu.Lock()
	mockAlerts = []SecurityAlert{} // Clear previous alerts as requested
	HandleSecurityAlerts(scanAlerts, scannedIDs)
	mu.Unlock()

	// Return summary
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "ok",
		"alerts_found": len(scanAlerts),
	})
}

func deviceHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	mu.RLock()
	client, ok := clients[id]
	status := "offline"
	isoStatus := "Normal"

	var data ClientView
	if ok {
		if time.Since(client.Timestamp) < 30*time.Second {
			status = "online"
		}
		if val, hasIso := isolationState[id]; hasIso {
			isoStatus = val
		}
		data = ClientView{
			ID:        id,
			OS:        client.OS, // these are fields on *Client
			Version:   client.Version,
			Status:    status,
			Isolation: isoStatus,
			History:   isolationLog[id], // Pass History to device_control.html too
		}
	}
	mu.RUnlock()

	if !ok {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	tmpl, err := template.ParseFS(templates, "templates/device_control.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

func screenImageHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.RLock()
	client, ok := clients[id]
	mu.RUnlock()

	if !ok || len(client.Frame) == 0 {
		http.Error(w, "No frame available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "image/jpeg")
	w.Write(client.Frame)
}

func screenViewHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	mu.RLock()
	client, ok := clients[id]
	status := "offline"
	isoStatus := "Normal"

	var data ClientView
	if ok {
		if time.Since(client.Timestamp) < 30*time.Second {
			status = "online"
		}
		if val, hasIso := isolationState[id]; hasIso {
			isoStatus = val
		}
		data = ClientView{
			ID:        id,
			OS:        client.OS,
			Version:   client.Version,
			Status:    status,
			Isolation: isoStatus,
			History:   isolationLog[id], // Pass the history logs
		}
	}
	mu.RUnlock()

	if !ok {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	tmpl, err := template.ParseFS(templates, "templates/screen_view.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, data)
}

func deleteAlertHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		log.Println("DeleteAlert: Unauthorized request")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != "POST" {
		log.Printf("DeleteAlert: Invalid method %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	log.Printf("DeleteAlert: Request to delete ID: %s", id)

	if id == "" {
		http.Error(w, "Missing alert ID", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	// Filter out the alert with the given ID
	newAlerts := []SecurityAlert{}
	found := false
	for _, alert := range mockAlerts {
		if alert.ID != id {
			newAlerts = append(newAlerts, alert)
		} else {
			found = true
		}
	}

	if found {
		log.Printf("DeleteAlert: Successfully deleted ID: %s", id)
		mockAlerts = newAlerts
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok"}`))
	} else {
		log.Printf("DeleteAlert: ID %s not found in mockAlerts (count: %d)", id, len(mockAlerts))
		http.Error(w, "Alert not found", http.StatusNotFound)
	}
}

func main() {
	// ... handlers
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler) // Added logout

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/notifications", notificationsHandler)
	http.HandleFunc("/delete-alert", deleteAlertHandler)


	http.HandleFunc("/device", deviceHandler) // Device Hub
	http.HandleFunc("/upload", clientHandler) // Was /client

	// Command & Terminal
	http.HandleFunc("/command", commandHandler)
	http.HandleFunc("/cmd/poll", pollCommandHandler) // Was /poll
	http.HandleFunc("/cmd/result", responseHandler)  // Was /response
	http.HandleFunc("/terminal", terminalHandler)
	http.HandleFunc("/terminal/updates", terminalUpdatesHandler)

	// Processes
	http.HandleFunc("/process", processHandler)            // View
	http.HandleFunc("/proc/poll", procPollHandler)         // NEW: Client poll for process cmds
	http.HandleFunc("/proc/result", processResultHandler)  // Was /process/result
	http.HandleFunc("/process/paths", processPathsHandler) // Detailed view?

	// Services
	http.HandleFunc("/services", servicesHandler)           // View services
	http.HandleFunc("/svc/poll", svcPollHandler)            // Client poll for service cmds
	http.HandleFunc("/svc/result", svcResultHandler)        // Client response with services
	http.HandleFunc("/svc/stop/poll", svcStopPollHandler)   // Client poll for stop service cmds
	http.HandleFunc("/svc/start/poll", svcStartPollHandler) // Client poll for start service cmds

	// Screen
	http.HandleFunc("/screen/image", screenImageHandler) // Serve raw JPEG
	http.HandleFunc("/screen/view", screenViewHandler)   // Serve HTML viewer

	// Files
	http.HandleFunc("/file", fileExplorerHandler)      // UI path
	http.HandleFunc("/file/poll", filePollHandler)     // Client poll
	http.HandleFunc("/file/result", fileResultHandler) // Client response

	// EDR / Isolation
	http.HandleFunc("/api/isolate", isolationHandler) // Trigger isolation
	http.HandleFunc("/edr/cmd/poll", edrPollHandler)  // Was /edr/poll

	// AI Scanner
	http.HandleFunc("/trigger-scan", scanHandler)

	fmt.Printf("Server listening on %s\n", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
