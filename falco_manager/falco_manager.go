package falco_manager

import (
	"akagent/internal/systemd"
	"akagent/logger"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rs/xid"
)

const (
	testRule string = "Test rule"
	syscalls string = "syscalls"
	syscall  string = "syscall"
)

var (
	log = logger.Sublogger("falco-listener")
)

type FalcoMessage struct {
	// Define your Falco message structure here
}

type GenericMessage map[string]interface{}

type FalcoFilesGetResult struct {
	FalcoFiles []FalcoRuleFileData `json:"falco_files"`
}

type FalcoRuleFileData struct {
	Filename string `json:"filename"`
	MD5Sum   string `json:"md5sum"`
	Content  string `json:"content"`
}

type FalcoManager struct {
	rulesFiles    []string
	ruleFilesData []FalcoRuleFileData
	listner       *http.Server
	MessageChan   chan FalcoEventPayload
}

func NewFalcoManager() *FalcoManager {
	return &FalcoManager{
		listner:       nil,
		MessageChan:   make(chan FalcoEventPayload, 1000),
		rulesFiles:    []string{},
		ruleFilesData: []FalcoRuleFileData{},
	}
}

func (fm *FalcoManager) StartListener() {
	log.Info().Msg("Starting falco listner")

	routes := map[string]http.Handler{
		"/":        http.HandlerFunc(fm.mainHandler),
		"/ping":    http.HandlerFunc(pingHandler),
		"/healthz": http.HandlerFunc(healthHandler),
	}

	mainServeMux := http.NewServeMux()

	// configure main server routes
	for r, handler := range routes {
		mainServeMux.Handle(r, handler)
	}

	fm.LoadRules()

	fm.listner = &http.Server{
		// TODO: get the ip and port from the config
		Addr:    fmt.Sprintf("%s:%d", "127.0.0.1", 2801),
		Handler: mainServeMux,
		// Timeouts
		ReadTimeout:       60 * time.Second,
		ReadHeaderTimeout: 60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	fmt.Println("Starting HTTP server on port 2801")
	if err := fm.listner.ListenAndServe(); err != nil {
		fmt.Printf("[ERROR] : %v", err.Error())
	}
}

func (fm *FalcoManager) Listening() bool {
	return fm.listner != nil
}

func (fm *FalcoManager) StopListener() {
	if fm.listner != nil {
		fm.listner.Shutdown(context.Background())
		fm.listner = nil
	}
}

func (fm *FalcoManager) FalcoServiceAgentRunning() string {
	serviceStatus := systemd.CheckServiceStatus("falco-modern-bpf.service")
	if serviceStatus == 0 {
		return "running"
	}
	return "stopped"
}

func (fm *FalcoManager) LoadRules() {
	// First get the list of rules files
	rulesFiles, err := ListFalcoRulesFiles()
	if err != nil {
		log.Err(err).Msg("Error listing Falco rules files")
		fm.ruleFilesData = []FalcoRuleFileData{}
		return
	}
	fm.rulesFiles = rulesFiles
	log.Debug().Msgf("Found %d Falco rules files", len(rulesFiles))

	fm.ruleFilesData = make([]FalcoRuleFileData, len(rulesFiles))
	for i, ruleFile := range rulesFiles {
		log.Debug().Msgf("Reading Falco rule file %s", ruleFile)
		ruleFileData, err := ReadFalcoRuleFile(ruleFile)
		md5sum := md5.Sum([]byte(ruleFileData))
		if err != nil {
			log.Err(err).Msgf("Error reading Falco rule file %s", ruleFile)
			continue
		}
		encodedContent := base64.StdEncoding.EncodeToString([]byte(ruleFileData))
		fm.ruleFilesData[i] = FalcoRuleFileData{
			Filename: ruleFile,
			MD5Sum:   fmt.Sprintf("%x", md5sum),
			Content:  encodedContent,
		}
		log.Debug().Msgf("Loaded rule file %s", ruleFile)
	}
}

func (fm *FalcoManager) UpdateRuleFiles(ruleFiles []FalcoRuleFileData) {
	// First get the list of rules files and create a map of the existing files, so we can
	// delete the ones that are not in the new list
	existingRulesFiles, err := ListFalcoRulesFiles()
	if err != nil {
		log.Err(err).Msg("Error loading existing rules files")
	}
	existingRulesFilesMap := make(map[string]bool)
	for _, ruleFile := range existingRulesFiles {
		existingRulesFilesMap[ruleFile] = true
	}
	log.Debug().Msgf("Existing rules files map: %v", existingRulesFilesMap)

	// decode the content of each rule file
	decodedRuleFiles := make([]FalcoRuleFileData, len(ruleFiles))
	for i, ruleFile := range ruleFiles {
		log.Debug().Msgf("Decoding Falco rule file %s", ruleFile.Filename)
		log.Debug().Msgf("MD5Sum: %s", ruleFile.MD5Sum)
		// Validate base64 content
		if ruleFile.Content == "" {
			log.Error().Msgf("Empty content for rule file %s", ruleFile.Filename)
			continue
		}

		// Remove any whitespace from base64 string
		cleanContent := strings.TrimSpace(ruleFile.Content)

		decodedContent, err := base64.StdEncoding.DecodeString(cleanContent)
		if err != nil {
			log.Error().
				Err(err).
				Str("filename", ruleFile.Filename).
				// Str("content_preview", cleanContent[:min(len(cleanContent), 20)]+"...").
				Msg("Error decoding base64 content")
			continue
		}
		// verify md5sum
		md5sum := md5.Sum([]byte(decodedContent))
		if fmt.Sprintf("%x", md5sum) != ruleFile.MD5Sum {
			log.Error().
				Str("filename", ruleFile.Filename).
				Str("expected", ruleFile.MD5Sum).
				Str("calculated", fmt.Sprintf("%x", md5sum)).
				Msg("MD5 checksum mismatch")
			continue
		}

		decodedRuleFiles[i] = FalcoRuleFileData{
			Filename: ruleFile.Filename,
			MD5Sum:   ruleFile.MD5Sum,
			Content:  string(decodedContent),
		}
	}

	// write the updated rule files to the file system
	for _, ruleFile := range decodedRuleFiles {
		err := WriteFalcoRuleFile(ruleFile.Filename, ruleFile.Content)
		if err != nil {
			log.Err(err).Msgf("Error writing Falco rule file %s", ruleFile.Filename)
			continue
		}
		log.Debug().Msgf("Updated Falco rule file %s", ruleFile.Filename)
		existingRulesFilesMap[ruleFile.Filename] = true
	}

	// delete the files that are not in the new list
	for _, ruleFile := range existingRulesFiles {
		if !existingRulesFilesMap[ruleFile] {
			log.Debug().Msgf("Deleting falco rule file %s", ruleFile)
			err := DeleteFalcoRuleFile(ruleFile)
			if err != nil {
				log.Err(err).Msgf("Error deleting falco rule file %s", ruleFile)
			}
		}
	}

	log.Info().Msg("Rules files updated, restarting Falco service")
	returnCode := systemd.RestartService("falco-modern-bpf.service")
	if returnCode != 0 {
		log.Error().Msgf("Failed to restart Falco service, return code: %d", returnCode)
	}

}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (fm *FalcoManager) ListFalcoRulesFiles() []string {
	return fm.rulesFiles
}

func (fm *FalcoManager) RuleFilesDataJson() ([]byte, error) {
	data, err := json.Marshal(fm.ruleFilesData)
	if err != nil {
		log.Err(err).Msg("Error marshalling Falco rule files data")
		return nil, err
	}
	return data, nil
}

// Only used for debugging at falco manage level.
// // start a message processor for channel
// func (fm *FalcoManager) StartMessageProcessor(ctx context.Context) {
// 	log.Debug().Msg("Starting FalcoListner message processor")
// 	for {
// 		select {
// 		case <-ctx.Done():
// 			log.Debug().Msg("Stopping FalcoListner message processor")
// 			return
// 		case message := <-fm.MessageChan:
// 			displayMessage(message)
// 		}
// 	}
// }

// func displayMessage(message FalcoEventPayload) {
// 	// Process the received Falco message
// 	fmt.Println("Received Falco message:")
// 	fmt.Println(message.String())
// 	fmt.Println("---")
// }

func (fm *FalcoManager) mainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		log.Debug().Msg("Received empty request body")
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Please send with post http method", http.StatusBadRequest)
		log.Debug().Msg("Received request with invalid http method")
		return
	}

	falcopayload, err := newFalcoPayload(r.Body)
	if err != nil || !falcopayload.Check() {
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		log.Debug().Msg("Received invalid request body")
		return
	}

	// forwardEvent(falcopayload)
	fm.MessageChan <- falcopayload // this is processed by agent.StartFalcoEventSender
	log.Debug().Msgf("Forwarded falco event to channel: %v", falcopayload)
}

// healthHandler is a simple handler to test if daemon is UP.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	// #nosec G104 nothing to be done if the following fails
	w.Write([]byte(`{"status": "ok"}`))
}

// pingHandler is a simple handler to test if daemon is UP.
func pingHandler(w http.ResponseWriter, r *http.Request) {
	// #nosec G104 nothing to be done if the following fails
	w.Write([]byte("pong\n"))
}

func newFalcoPayload(payload io.Reader) (FalcoEventPayload, error) {
	var falcopayload FalcoEventPayload

	d := json.NewDecoder(payload)
	d.UseNumber()

	err := d.Decode(&falcopayload)
	if err != nil {
		log.Err(err).Msg("Error decoding Falco payload")
		return FalcoEventPayload{}, err
	}

	// var customFields string
	// if len(config.Customfields) > 0 {
	// 	if falcopayload.OutputFields == nil {
	// 		falcopayload.OutputFields = make(map[string]interface{})
	// 	}
	// 	for key, value := range config.Customfields {
	// 		customFields += key + "=" + value + " "
	// 		falcopayload.OutputFields[key] = value
	// 	}
	// }

	if falcopayload.Rule == "Test rule" {
		falcopayload.Source = "internal"
	}

	if falcopayload.Source == "" {
		falcopayload.Source = syscalls
	}

	falcopayload.UUID = xid.New().String()

	var kn, kp string
	for i, j := range falcopayload.OutputFields {
		if j != nil {
			if i == "k8s.ns.name" {
				kn = j.(string)
			}
			if i == "k8s.pod.name" {
				kp = j.(string)
			}
		}
	}

	log.Debug().Msgf("falcopayload %v", falcopayload)

	// var templatedFields string
	// if len(config.Templatedfields) > 0 {
	// 	if falcopayload.OutputFields == nil {
	// 		falcopayload.OutputFields = make(map[string]interface{})
	// 	}
	// 	for key, value := range config.Templatedfields {
	// 		tmpl, err := template.New("").Parse(value)
	// 		if err != nil {
	// 			log.Printf("[ERROR] : Parsing error for templated field '%v': %v\n", key, err)
	// 			continue
	// 		}
	// 		v := new(bytes.Buffer)
	// 		if err := tmpl.Execute(v, falcopayload.OutputFields); err != nil {
	// 			log.Printf("[ERROR] : Parsing error for templated field '%v': %v\n", key, err)
	// 		}
	// 		templatedFields += key + "=" + v.String() + " "
	// 		falcopayload.OutputFields[key] = v.String()
	// 	}
	// }

	if len(falcopayload.Tags) != 0 {
		sort.Strings(falcopayload.Tags)
	}

	promLabels := map[string]string{"rule": falcopayload.Rule, "priority": falcopayload.Priority.String(), "source": falcopayload.Source, "k8s_ns_name": kn, "k8s_pod_name": kp}
	if falcopayload.Hostname != "" {
		promLabels["hostname"] = falcopayload.Hostname
	} else {
		promLabels["hostname"] = "unknown"
	}

	// for key, value := range config.Customfields {
	// 	if regPromLabels.MatchString(key) {
	// 		promLabels[key] = value
	// 	}
	// }

	// for _, i := range config.Prometheus.ExtraLabelsList {
	// 	promLabels[strings.ReplaceAll(i, ".", "_")] = ""
	// 	for key, value := range falcopayload.OutputFields {
	// 		if key == i && regPromLabels.MatchString(strings.ReplaceAll(key, ".", "_")) {
	// 			switch value.(type) {
	// 			case string:
	// 				promLabels[strings.ReplaceAll(key, ".", "_")] = fmt.Sprintf("%v", value)
	// 			default:
	// 				continue
	// 			}
	// 		}
	// 	}
	// }

	for i, j := range falcopayload.OutputFields {
		if strings.Contains(i, "[") {
			falcopayload.OutputFields[strings.ReplaceAll(strings.ReplaceAll(i, "]", ""), "[", "")] = j
			delete(falcopayload.OutputFields, i)
		}
	}

	// if config.OutputFieldFormat != "" && regOutputFormat.MatchString(falcopayload.Output) {
	// 	outputElements := strings.Split(falcopayload.Output, " ")
	// 	if len(outputElements) >= 3 {
	// 		t := strings.TrimSuffix(outputElements[0], ":")
	// 		p := cases.Title(language.English).String(falcopayload.Priority.String())
	// 		o := strings.Join(outputElements[2:], " ")
	// 		n := config.OutputFieldFormat
	// 		n = strings.ReplaceAll(n, "<timestamp>", t)
	// 		n = strings.ReplaceAll(n, "<priority>", p)
	// 		n = strings.ReplaceAll(n, "<output>", o)
	// 		n = strings.ReplaceAll(n, "<custom_fields>", strings.TrimSuffix(customFields, " "))
	// 		n = strings.ReplaceAll(n, "<templated_fields>", strings.TrimSuffix(templatedFields, " "))
	// 		n = strings.TrimSuffix(n, " ")
	// 		n = strings.TrimSuffix(n, " ")
	// 		n = strings.TrimSuffix(n, "( )")
	// 		n = strings.TrimSuffix(n, "()")
	// 		n = strings.TrimSuffix(n, " ")
	// 		falcopayload.Output = n
	// 	}
	// }

	if len(falcopayload.String()) > 4096 {
		for i, j := range falcopayload.OutputFields {
			switch v := j.(type) {
			case string:
				if len(v) > 512 {
					k := v[:507] + "[...]"
					falcopayload.Output = strings.ReplaceAll(falcopayload.Output, v, k)
					falcopayload.OutputFields[i] = k
				}
			}
		}
	}

	log.Debug().Msgf("[DEBUG] : Falco's payload : %v\n", falcopayload.String())
	return falcopayload, nil
}
