package enrichment

import (
	"encoding/json"

	"github.com/refractionPOINT/lcre/internal/model"
)

func init() {
	RegisterParser(&DIECParser{})
}

// DIECParser parses Detect It Easy (diec) JSON output.
type DIECParser struct{}

func (p *DIECParser) ToolName() string { return "diec" }

// diecOutput represents the top-level diec --json structure:
//
//	{"detects": [{"filetype": "PE64", "values": [{"type": "Compiler", ...}]}]}
//
// Each entry in "detects" is a per-file grouping; actual detections are in "values".
type diecOutput struct {
	Detects []diecFileGroup `json:"detects"`
}

// diecFileGroup is a per-file entry containing grouped detection values.
type diecFileGroup struct {
	Filetype string       `json:"filetype"`
	Values   []diecDetect `json:"values"`
}

type diecDetect struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	String  string `json:"string"`
	Version string `json:"version"`
}

func (p *DIECParser) Parse(data []byte) (*Result, error) {
	// Try the real diec --json format: {"detects": [{"values": [...]}]}
	var output diecOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, err
	}

	var detections []model.PackerDetection
	for _, group := range output.Detects {
		for _, d := range group.Values {
			detections = append(detections, model.PackerDetection{
				Type:    d.Type,
				Name:    d.Name,
				Version: d.Version,
				String:  d.String,
			})
		}
	}

	return &Result{
		Detections: detections,
	}, nil
}
