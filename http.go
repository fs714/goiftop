package main

import (
	"encoding/json"
	"net/http"
)

func L3FlowHandler(w http.ResponseWriter, r *http.Request) {
	resJson, err := json.Marshal(L3FlowSnapshots)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resJson)
}

func L4FlowHandler(w http.ResponseWriter, r *http.Request) {
	resJson, err := json.Marshal(L4FlowSnapshots)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resJson)
}
