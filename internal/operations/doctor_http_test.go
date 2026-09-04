package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const explicitDoctorURLCanary = "https://probe.example.test/health/check?case=explicit-canary"

func TestDoctorExplicitURLIsHTTPSOnlyRedactingAndNonSerializable(t *testing.T) {
	t.Parallel()

	probeURL, err := NewDoctorProbeURL(explicitDoctorURLCanary)
	if err != nil {
		t.Fatal(err)
	}
	if !probeURL.Present() || fmt.Sprint(probeURL) != "<sensitive-url>" || fmt.Sprintf("%#v", probeURL) != "<sensitive-url>" {
		t.Fatalf("probe URL formatting is unsafe: %v / %#v", probeURL, probeURL)
	}
	if encoded, err := json.Marshal(probeURL); err == nil || encoded != nil {
		t.Fatalf("probe URL serialized: %q, %v", encoded, err)
	}
	if encoded, err := json.Marshal(DoctorOptions{ProbeURL: probeURL}); err == nil || encoded != nil {
		t.Fatalf("doctor options serialized explicit URL: %q, %v", encoded, err)
	}
	var used string
	if err := probeURL.Use(func(value string) error { used = value; return nil }); err != nil || used != explicitDoctorURLCanary {
		t.Fatalf("probe URL use = %q, %v", used, err)
	}
	for _, invalid := range []string{
		"", "http://probe.example.test/health", "https://user:pass@probe.example.test/health",
		"https://probe.example.test/health#fragment", "/relative", " https://probe.example.test/health", "https://probe.example.test:0/health",
	} {
		if _, err := NewDoctorProbeURL(invalid); err == nil {
			t.Fatalf("invalid probe URL accepted: %q", invalid)
		}
	}
}

func TestExplicitGETDoctorRunnerSendsOneCredentialFreeNonRedirectingGET(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	state := doctorNodeState(t, now)
	source := &auditedStatusStateSource{state: state}
	before := cloneStatusTestState(t, state)
	base := &recordingDoctorRunner{}
	roundTripper := &recordingDoctorRoundTripper{status: http.StatusNoContent}
	runner, err := NewExplicitGETDoctorRunner(base, roundTripper)
	if err != nil {
		t.Fatal(err)
	}
	doctor, err := NewDoctor(model.RoleNode, source, runner, DoctorLimits{}, fixedDoctorRunID)
	if err != nil {
		t.Fatal(err)
	}
	probeURL, err := NewDoctorProbeURL(explicitDoctorURLCanary)
	if err != nil {
		t.Fatal(err)
	}
	report, err := doctor.RunWithOptions(context.Background(), DoctorScopeDefault, DoctorOptions{ProbeURL: probeURL})
	if err != nil {
		t.Fatal(err)
	}
	if report.Overall != StatusOverallHealthy || len(report.Checks) != 15 || len(base.Requests()) != 14 || roundTripper.calls != 1 || !roundTripper.bodyClosed {
		t.Fatalf("explicit doctor report/base/http = %+v / %d / %+v", report, len(base.Requests()), roundTripper)
	}
	request := roundTripper.request
	if request == nil || request.Method != http.MethodGet || request.URL.String() != explicitDoctorURLCanary || request.Body != nil || request.GetBody != nil ||
		request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || len(request.Header) != 1 ||
		request.Header.Get("User-Agent") != "vpnctl-doctor/"+doctorRunID+"-015" {
		t.Fatalf("unsafe explicit request = %+v headers=%+v", request, request.Header)
	}
	if request.URL.User != nil || !reflect.DeepEqual(source.state, before) || source.writes != 0 || base.switches != 0 || base.applies != 0 || base.repairs != 0 || base.webhooks != 0 {
		t.Fatalf("explicit probe mutated state or invoked forbidden operation: source=%+v base=%+v", source, base)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(explicitDoctorURLCanary)) || strings.Contains(fmt.Sprintf("%+v", DoctorOptions{ProbeURL: probeURL}), explicitDoctorURLCanary) {
		t.Fatalf("explicit URL leaked through report/options: %s / %+v", encoded, DoctorOptions{ProbeURL: probeURL})
	}
	found := false
	for _, check := range report.Checks {
		found = found || check.Kind == DoctorProbeExternalHTTPS && check.Status == DoctorCheckPassed && check.Code == "explicit_https_get_passed"
	}
	if !found {
		t.Fatalf("explicit GET result missing: %+v", report.Checks)
	}
}

func TestDoctorSkipsUnknownExternalDependencyWithExplanation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	base := &recordingDoctorRunner{}
	doctor, err := NewDoctor(model.RoleNode, &auditedStatusStateSource{state: doctorNodeState(t, now)}, base, DoctorLimits{}, fixedDoctorRunID)
	if err != nil {
		t.Fatal(err)
	}
	report, err := doctor.Run(context.Background(), DoctorScopeIngress)
	if err != nil {
		t.Fatal(err)
	}
	if report.Overall != StatusOverallHealthy || len(base.Requests()) != 4 || len(report.Checks) != 5 {
		t.Fatalf("unknown external dependency result = %+v requests=%+v", report, base.Requests())
	}
	found := false
	for _, check := range report.Checks {
		if check.Kind == DoctorProbeExternalHTTPS {
			found = check.Status == DoctorCheckSkipped && check.Code == "external_endpoint_unspecified" &&
				strings.Contains(check.Detail, "hidden vpnctl telemetry")
		}
	}
	if !found || base.webhooks != 0 {
		t.Fatalf("external dependency was not safely skipped: %+v base=%+v", report.Checks, base)
	}
}

func TestExplicitGETDoctorRunnerRefusesRedirectWithoutFollowingIt(t *testing.T) {
	t.Parallel()

	probeURL, err := NewDoctorProbeURL(explicitDoctorURLCanary)
	if err != nil {
		t.Fatal(err)
	}
	transport := &recordingDoctorRoundTripper{status: http.StatusFound}
	runner, err := NewExplicitGETDoctorRunner(&recordingDoctorRunner{}, transport)
	if err != nil {
		t.Fatal(err)
	}
	request := DoctorProbeRequest{
		ProbeID: doctorRunID + "-001", Scope: DoctorScopeExternal, Name: "external.explicit_https_get",
		Kind: DoctorProbeExternalHTTPS, Protocol: DoctorProtocolHTTPS, ResourceKind: "external_dependency", ResourceID: "explicit",
		HTTPMethod: "GET", FollowRedirects: false, ProbeURL: probeURL,
	}
	result, err := runner.Probe(context.Background(), request)
	if err != nil || result.Passed || result.Code != "explicit_https_redirect_refused" || transport.calls != 1 {
		t.Fatalf("redirect result = %+v, %v calls=%d", result, err, transport.calls)
	}
}

type recordingDoctorRoundTripper struct {
	request    *http.Request
	status     int
	calls      int
	bodyClosed bool
}

func (transport *recordingDoctorRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls++
	transport.request = request
	body := &doctorCloseRecorder{onClose: func() { transport.bodyClosed = true }}
	return &http.Response{StatusCode: transport.status, Header: make(http.Header), Body: body, Request: request}, nil
}

type doctorCloseRecorder struct{ onClose func() }

func (*doctorCloseRecorder) Read([]byte) (int, error) { return 0, io.EOF }
func (body *doctorCloseRecorder) Close() error {
	body.onClose()
	return nil
}
