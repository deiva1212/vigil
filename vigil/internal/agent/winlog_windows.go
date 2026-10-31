//go:build windows

package agent

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vigil-siem/vigil/internal/common"
)

type winEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Level       string `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID uint64 `xml:"EventRecordID"`
		Channel       string `xml:"Channel"`
		Computer      string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// Sigma/Windows field names -> Vigil ECS names (originals are kept too).
var winFieldMap = map[string]string{
	"Image": "process.executable", "NewProcessName": "process.executable", "CommandLine": "process.command_line",
	"ParentImage": "process.parent.executable", "ParentProcessName": "process.parent.executable",
	"ParentCommandLine": "process.parent.command_line", "ProcessId": "process.pid", "NewProcessId": "process.pid",
	"User": "user.name", "TargetUserName": "user.target", "SubjectUserName": "user.name",
	"IpAddress": "source.ip", "IpPort": "source.port", "SourceIp": "source.ip", "DestinationIp": "destination.ip",
	"DestinationPort": "destination.port", "TargetFilename": "file.path", "LogonType": "winlog.logon.type",
}

func wevtutil(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "wevtutil", args...).Output()
}

func parseWinEvents(b []byte) []winEvent {
	dec := xml.NewDecoder(bytes.NewReader(append(append([]byte("<Events>"), b...), []byte("</Events>")...)))
	var wrap struct {
		Events []winEvent `xml:"Event"`
	}
	dec.Decode(&wrap)
	return wrap.Events
}

func channelService(ch string) string {
	l := strings.ToLower(ch)
	switch {
	case strings.Contains(l, "sysmon"):
		return "sysmon"
	case strings.Contains(l, "powershell"):
		return "powershell"
	}
	return l
}

// RunWinlog polls each channel for records newer than the last one seen.
func RunWinlog(cfg *Config, ship *Shipper, stop <-chan struct{}) {
	stateF := filepath.Join(cfg.StateDir, "winlog.json")
	last := map[string]uint64{}
	loadJSON(stateF, &last)
	for _, ch := range cfg.WinChannels {
		if _, ok := last[ch]; ok {
			continue
		}
		b, err := wevtutil("qe", ch, "/c:1", "/rd:true", "/f:xml")
		if err != nil {
			log.Printf("winlog: channel %s unavailable: %v", ch, err)
			continue
		}
		if evs := parseWinEvents(b); len(evs) > 0 {
			last[ch] = evs[0].System.EventRecordID
		} else {
			last[ch] = 0
		}
	}
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		for ch, id := range last {
			q := fmt.Sprintf("/q:*[System[EventRecordID>%d]]", id)
			b, err := wevtutil("qe", ch, q, "/c:500", "/rd:false", "/f:xml")
			if err != nil {
				continue
			}
			for _, ev := range parseWinEvents(b) {
				if ev.System.EventRecordID > last[ch] {
					last[ch] = ev.System.EventRecordID
				}
				ship.Emit(convertWinEvent(ch, ev))
			}
		}
		saveJSON(stateF, last)
		select {
		case <-stop:
			return
		case <-tick.C:
		}
	}
}

func convertWinEvent(ch string, ev winEvent) *common.Event {
	f := map[string]string{
		"event.code": ev.System.EventID, "EventID": ev.System.EventID, "event.provider": ev.System.Provider.Name,
		"log.service": channelService(ch), "winlog.channel": ch, "winlog.record_id": strconv.FormatUint(ev.System.EventRecordID, 10),
		"host.name": ev.System.Computer, "os.type": "windows",
	}
	var parts []string
	for _, d := range ev.EventData.Data {
		if d.Name == "" {
			continue
		}
		v := strings.TrimSpace(d.Value)
		f[d.Name] = v
		if m, ok := winFieldMap[d.Name]; ok && v != "" && v != "-" {
			f[m] = v
		}
		if len(parts) < 12 && v != "" && v != "-" {
			parts = append(parts, d.Name+"="+v)
		}
	}
	cat := "log"
	svc := channelService(ch)
	if (svc == "sysmon" && ev.System.EventID == "1") || (svc == "security" && ev.System.EventID == "4688") {
		cat = "process"
		if exe := f["process.executable"]; exe != "" {
			f["process.name"] = filepath.Base(strings.ReplaceAll(exe, `\`, "/"))
		}
	}
	ts, _ := time.Parse(time.RFC3339Nano, ev.System.TimeCreated.SystemTime)
	return &common.Event{Category: cat, Source: "windows:" + ch, Timestamp: ts, Fields: f,
		Raw: fmt.Sprintf("%s EventID %s: %s", ev.System.Provider.Name, ev.System.EventID, strings.Join(parts, " "))}
}
