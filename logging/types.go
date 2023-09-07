package logging

// PacketType is the packet type of a QUIC packet
type PacketType uint8

const (
	// PacketTypeInitial is the packet type of an Initial packet
	PacketTypeInitial PacketType = iota
	// PacketTypeHandshake is the packet type of a Handshake packet
	PacketTypeHandshake
	// PacketTypeRetry is the packet type of a Retry packet
	PacketTypeRetry
	// PacketType0RTT is the packet type of a 0-RTT packet
	PacketType0RTT
	// PacketTypeVersionNegotiation is the packet type of a Version Negotiation packet
	PacketTypeVersionNegotiation
	// PacketType1RTT is a 1-RTT packet
	PacketType1RTT
	// PacketTypeStatelessReset is a stateless reset
	PacketTypeStatelessReset
	// PacketTypeNotDetermined is the packet type when it could not be determined
	PacketTypeNotDetermined
)

type PacketLossReason uint8

const (
	// PacketLossReorderingThreshold: when a packet is deemed lost due to reordering threshold
	PacketLossReorderingThreshold PacketLossReason = iota
	// PacketLossTimeThreshold: when a packet is deemed lost due to time threshold
	PacketLossTimeThreshold
)

type PacketDropReason uint8

const (
	// PacketDropKeyUnavailable is used when a packet is dropped because keys are unavailable
	PacketDropKeyUnavailable PacketDropReason = iota
	// PacketDropUnknownConnectionID is used when a packet is dropped because the connection ID is unknown
	PacketDropUnknownConnectionID
	// PacketDropHeaderParseError is used when a packet is dropped because header parsing failed
	PacketDropHeaderParseError
	// PacketDropPayloadDecryptError is used when a packet is dropped because decrypting the payload failed
	PacketDropPayloadDecryptError
	// PacketDropProtocolViolation is used when a packet is dropped due to a protocol violation
	PacketDropProtocolViolation
	// PacketDropDOSPrevention is used when a packet is dropped to mitigate a DoS attack
	PacketDropDOSPrevention
	// PacketDropUnsupportedVersion is used when a packet is dropped because the version is not supported
	PacketDropUnsupportedVersion
	// PacketDropUnexpectedPacket is used when an unexpected packet is received
	PacketDropUnexpectedPacket
	// PacketDropUnexpectedSourceConnectionID is used when a packet with an unexpected source connection ID is received
	PacketDropUnexpectedSourceConnectionID
	// PacketDropUnexpectedVersion is used when a packet with an unexpected version is received
	PacketDropUnexpectedVersion
	// PacketDropDuplicate is used when a duplicate packet is received
	PacketDropDuplicate
)

// TimerType is the type of the loss detection timer
type TimerType uint8

const (
	// TimerTypeACK is the timer type for the early retransmit timer
	TimerTypeACK TimerType = iota
	// TimerTypePTO is the timer type for the PTO retransmit timer
	TimerTypePTO
)

// TimeoutReason is the reason why a session is closed
type TimeoutReason uint8

const (
	// TimeoutReasonHandshake is used when the session is closed due to a handshake timeout
	// This reason is not defined in the qlog draft, but very useful for debugging.
	TimeoutReasonHandshake TimeoutReason = iota
	// TimeoutReasonIdle is used when the session is closed due to an idle timeout
	// This reason is not defined in the qlog draft, but very useful for debugging.
	TimeoutReasonIdle
)

type CongestionState uint8

const (
	// CongestionStateSlowStart is the slow start phase of Reno / Cubic
	CongestionStateSlowStart CongestionState = iota
	// CongestionStateCongestionAvoidance is the slow start phase of Reno / Cubic
	CongestionStateCongestionAvoidance
	// CongestionStateCongestionAvoidance is the recovery phase of Reno / Cubic
	CongestionStateRecovery
	// CongestionStateApplicationLimited means that the congestion controller is application limited
	CongestionStateApplicationLimited
)

type ECNValidationResult uint8

const (
	// Initial ECN validation succeeded
	ECNValidationSuccess ECNValidationResult = iota
	// ECN validation failed because an ACK lacked required ECN counters
	ECNValidationMissingCounters
	// ECN validation failed because an ECN counter decreased
	ECNValidationDecreasingECT0
	ECNValidationDecreasingECT1
	ECNValidationDecreasingCE
	// ECN validation failed because sent packets were illegally remarked in the network
	ECNValidationMissingECT0 // from ECT0 to Not-ECT
	ECNValidationMissingECT1 // from ECT1 to Not-ECT
	ECNValidationIllegalECT0 // from any to ECT0
	ECNValidationIllegalECT1 // from any to ECT1
	ECNValidationMissingCE   // from CE to Not-ECT or ECT0
	// Initial ECN validation failed because all sent packets were reported as CE
	ECNValidationAllCE
	// Initial ECN validation failed because all sent packets were declared lost
	ECNValidationAllLost
)

func (r ECNValidationResult) String() string {
	switch r {
	case ECNValidationSuccess:
		return "success"
	case ECNValidationMissingCounters:
		return "failed (missing ECN counters in ACK)"
	case ECNValidationDecreasingECT0:
		return "failed (ECT0 counter decreased)"
	case ECNValidationDecreasingECT1:
		return "failed (ECT1 counter decreased)"
	case ECNValidationDecreasingCE:
		return "failed (CE counter decreased)"
	case ECNValidationIllegalECT0:
		return "failed (sent packets were illegally remarked to ECT0)"
	case ECNValidationIllegalECT1:
		return "failed (sent packets were illegally remarked to ECT1)"
	case ECNValidationMissingECT0:
		return "failed (sent packets were illegally remarked from ECT0)"
	case ECNValidationMissingECT1:
		return "failed (sent packets were illegally remarked from ECT1)"
	case ECNValidationMissingCE:
		return "failed (sent packets were illegally remarked from CE)"
	case ECNValidationAllCE:
		return "failed (all sent packets were reported as CE)"
	case ECNValidationAllLost:
		return "failed (all sent packets were declared lost)"
	}
	return "invalid ECNValidationResult value"
}
