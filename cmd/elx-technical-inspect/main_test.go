package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
)

func TestOfflineTechnicalInspectionNeverMutatesUncertainJournal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("durable journal requires Unix directory fsync")
	}
	path := filepath.Join(t.TempDir(), "operations.json")
	statePath := filepath.Join(filepath.Dir(path), "policy.json")
	if err := os.WriteFile(statePath, []byte("managed state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	store, resource, node, executor, profile, prepare := uuid.NewString(),
		uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	if err := elxjournal.Provision(path, store); err != nil { t.Fatal(err) }
	j, err := elxjournal.Open(path)
	if err != nil { t.Fatal(err) }
	if err := j.BootstrapResource(resource, 1, 1); err != nil { t.Fatal(err) }
	digest := sha256.Sum256([]byte("operator signed intent"))
	p := elxjournal.TechnicalProfile{
		ProfileID: profile, OperationID: prepare, ResourceID: resource,
		NodeID: node, ExecutorID: executor, SubscriptionID: "lab",
		Email: "technical@lab", InboundTag: "vless",
		ProfileGeneration: 1, AuthorityGeneration: 1, PolicyRevision: 1,
		NotAfterUnix: time.Now().Add(time.Hour).Unix(),
		TranscriptSHA256: hex.EncodeToString(digest[:]), Phase: "PREPARED",
	}
	if err := j.RecordTechnicalPrepared(p); err != nil {t.Fatal(err)}
	install := uuid.NewString()
	if _, err := j.BeginTechnicalInstall(profile,install,hex.EncodeToString(digest[:]),"",1,1); err != nil {t.Fatal(err)}
	imageBefore, err := os.ReadFile(path); if err != nil {t.Fatal(err)}
	anchorBefore, err := os.ReadFile(path+".anchor"); if err != nil {t.Fatal(err)}
	args := []string{"-journal",path,"-policy-state",statePath,"-expect-store",store,
		"-profile",profile,"-operation",install}
	var out bytes.Buffer
	if err := inspect(args,&out);err != nil {t.Fatal(err)}
	var result technicalInspection
	if err := json.Unmarshal(out.Bytes(),&result);err != nil {t.Fatal(err)}
	if result.Phase!="INSTALLING" || !result.Uncertain ||
		!result.RequiresIsolation || result.MutationAllowed {
		t.Fatalf("incomplete signed INSTALL was not quarantined: %+v",result)
	}
	if err := inspect(append(args,"-require-terminal"),&bytes.Buffer{});err == nil {
		t.Fatal("operator terminal-state gate admitted uncertain INSTALL")
	}
	wrongStore := append([]string(nil), args...)
	wrongStore[5]=uuid.NewString()
	if err := inspect(wrongStore,&bytes.Buffer{});err == nil {
		t.Fatal("foreign store accepted as independent Control witness")
	}
	wrongOperation := append([]string(nil), args...)
	wrongOperation[9]=uuid.NewString()
	if err := inspect(wrongOperation,&bytes.Buffer{});err == nil {
		t.Fatal("unrelated Control operation accepted")
	}
	imageAfter, err := os.ReadFile(path);if err != nil {t.Fatal(err)}
	anchorAfter, err := os.ReadFile(path+".anchor");if err != nil {t.Fatal(err)}
	if !bytes.Equal(imageBefore,imageAfter)||!bytes.Equal(anchorBefore,anchorAfter) {
		t.Fatal("forensic inspection modified durable image or anchor")
	}
	if _, err := j.MarkTechnicalInstalled(profile,install);err != nil {t.Fatal(err)}
	retire := uuid.NewString()
	if _, err := j.BeginTechnicalRetire(profile,retire,hex.EncodeToString(digest[:]),2,1,1);err != nil {t.Fatal(err)}
	args[9] = retire
	out.Reset()
	if err := inspect(args,&out);err != nil {t.Fatal(err)}
	if err := json.Unmarshal(out.Bytes(),&result);err != nil {t.Fatal(err)}
	if result.Phase!="RETIRING" || result.DeniedGeneration!=2 ||
		!result.RequiresIsolation {
		t.Fatalf("interrupted RETIRE lost permanent deny tombstone: %+v",result)
	}
}
