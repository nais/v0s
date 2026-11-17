package grpcapi

import (
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func teamFilter(team string) []string {
	if team == "" {
		return nil
	}
	return []string{team}
}

func validateScope(team, environment, workload string) error {
	if workload != "" && (team == "" || environment == "") {
		return invalidArgument("workload requires team and environment")
	}
	return nil
}

// Reject the removed teams field instead of silently turning an old client's
// filtered request into a tenant-wide read.
func rejectLegacyTeams(message proto.Message, field protowire.Number) error {
	unknown := message.ProtoReflect().GetUnknown()
	for len(unknown) > 0 {
		number, wireType, n := protowire.ConsumeTag(unknown)
		if n < 0 {
			return invalidArgument("malformed request")
		}
		unknown = unknown[n:]
		if number == field {
			return invalidArgument("teams is no longer supported; use team and regenerate the client")
		}
		n = protowire.ConsumeFieldValue(number, wireType, unknown)
		if n < 0 {
			return invalidArgument("malformed request")
		}
		unknown = unknown[n:]
	}
	return nil
}
