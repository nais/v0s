package v0sv1_test

import (
	"testing"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestFindingFilterWireCompatibility(t *testing.T) {
	var wire []byte
	wire = protowire.AppendString(protowire.AppendTag(wire, 6, protowire.BytesType), "CVE-1")
	for _, id := range []string{"CVE-2", "GHSA-1"} {
		wire = protowire.AppendString(protowire.AppendTag(wire, 13, protowire.BytesType), id)
	}
	var got v0sv1.FindingFilter
	if err := proto.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	want := &v0sv1.FindingFilter{VulnerabilityId: "CVE-1", VulnerabilityIds: []string{"CVE-2", "GHSA-1"}}
	if !proto.Equal(&got, want) {
		t.Fatalf("decoded filter = %v, want %v", &got, want)
	}
}

func TestRemovedCVSSWireCompatibility(t *testing.T) {
	descriptor := (&v0sv1.Vulnerability{}).ProtoReflect().Descriptor()
	if !descriptor.ReservedRanges().Has(6) || !descriptor.ReservedNames().Has("cvss") {
		t.Fatal("removed CVSS field number and name must remain reserved")
	}
	if descriptor.Fields().ByNumber(6) != nil || descriptor.Fields().ByName("cvss") != nil {
		t.Fatal("CVSS must not be exposed")
	}

	wire := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "CVE-1")
	cvss := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "nvd")
	wire = protowire.AppendBytes(protowire.AppendTag(wire, 6, protowire.BytesType), cvss)
	wire = protowire.AppendString(protowire.AppendTag(wire, 7, protowire.BytesType), "https://example.com/advisory")
	var got v0sv1.Vulnerability
	if err := proto.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	if got.GetId() != "CVE-1" || len(got.GetReferences()) != 1 || got.GetReferences()[0] != "https://example.com/advisory" {
		t.Fatalf("legacy CVSS data affected remaining fields: %v", &got)
	}
}
