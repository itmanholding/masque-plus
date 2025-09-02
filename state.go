package main

import (
    "encoding/json"
    "os"
)

type State struct {
    Endpoint string `json:"endpoint"`
    Socks    string `json:"socks"`
}

const stateFile = "state.json"

func SaveState(s State) error {
    data, err := json.MarshalIndent(s, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(stateFile, data, 0644)
}

func LoadState() (State, error) {
    var s State
    data, err := os.ReadFile(stateFile)
    if err != nil {
        return s, err
    }
    err = json.Unmarshal(data, &s)
    return s, err
}
