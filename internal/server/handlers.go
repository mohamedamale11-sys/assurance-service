package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"assurance_service/internal/audit"
	"assurance_service/internal/policy"
	"assurance_service/internal/privacy"
)

type Handler struct {
	Store        *audit.Store
	Policy       *policy.Engine
	SharedSecret string
	EventsPath   string
	RootsPath    string
	BatchSize    int
	KAnonymity   int
	DPEpsilon    float64
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true,
	})
}

func (h *Handler) IngestEvent(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorPayload("invalid body"))
		return
	}
	if h.SharedSecret != "" {
		if !verifySignature(body, r.Header.Get("X-Assurance-Signature"), h.SharedSecret) {
			writeJSON(w, http.StatusUnauthorized, errorPayload("invalid signature"))
			return
		}
	}

	var event audit.Event
	if err := json.Unmarshal(body, &event); err != nil {
		writeJSON(w, http.StatusBadRequest, errorPayload("invalid json"))
		return
	}
	if event.Type == "" {
		writeJSON(w, http.StatusBadRequest, errorPayload("event type required"))
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.ID == "" {
		if id, err := computeEventID(event); err == nil {
			event.ID = id
		}
	}

	rec, root, err := h.Store.AppendEvent(event)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorPayload("append failed"))
		return
	}
	payload := map[string]interface{}{
		"ok":     true,
		"record": rec,
	}
	if root != nil {
		payload["root"] = root
	}
	writeJSON(w, http.StatusOK, payload)
}

func (h *Handler) LatestRoot(w http.ResponseWriter, r *http.Request) {
	last, err := h.Store.LastRoot()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorPayload("root read failed"))
		return
	}
	payload := map[string]interface{}{
		"ok":              true,
		"last_root":       last,
		"current_root":    h.Store.CurrentBatchRoot(),
		"batch_size":      h.BatchSize,
		"k_anonymity":     h.KAnonymity,
		"dp_epsilon":      h.DPEpsilon,
		"server_time_utc": time.Now().UTC(),
	}
	writeJSON(w, http.StatusOK, payload)
}

func (h *Handler) VerifyAudit(w http.ResponseWriter, r *http.Request) {
	report := audit.Verify(h.EventsPath, h.RootsPath, h.BatchSize)
	status := http.StatusOK
	if !report.OK {
		status = http.StatusConflict
	}
	writeJSON(w, status, map[string]interface{}{"ok": report.OK, "report": report})
}

func (h *Handler) ListEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	events, err := readLastEvents(h.EventsPath, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorPayload("event read failed"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "items": events})
}

func (h *Handler) PolicyCheck(w http.ResponseWriter, r *http.Request) {
	var input policy.Input
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, errorPayload("invalid json"))
		return
	}
	decision, err := h.Policy.Evaluate(input)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorPayload(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "decision": decision})
}

func (h *Handler) PrivacyTokenSummary(w http.ResponseWriter, r *http.Request) {
	windowHours, _ := strconv.Atoi(r.URL.Query().Get("window_hours"))
	if windowHours <= 0 || windowHours > 168 {
		windowHours = 24
	}
	k, _ := strconv.Atoi(r.URL.Query().Get("k"))
	if k <= 0 {
		k = h.KAnonymity
	}
	eps, _ := strconv.ParseFloat(r.URL.Query().Get("epsilon"), 64)
	if eps <= 0 {
		eps = h.DPEpsilon
	}
	seed, _ := strconv.ParseInt(r.URL.Query().Get("seed"), 10, 64)

	counts, err := privacy.TokenCounts(h.EventsPath, time.Duration(windowHours)*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorPayload("aggregate failed"))
		return
	}
	summary := privacy.SummarizeTokenCounts(counts, k, eps, seed, windowHours)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "summary": summary})
}

func verifySignature(body []byte, header string, secret string) bool {
	if header == "" || secret == "" {
		return false
	}
	const prefix = "sha256="
	if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return false
	}
	provided := header[len(prefix):]
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	expected := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(provided))
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func errorPayload(msg string) map[string]interface{} {
	return map[string]interface{}{"ok": false, "error": msg}
}

func computeEventID(event audit.Event) (string, error) {
	payload, err := audit.StableJSON(event)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:]), nil
}
