package ackhandler

import (
	"errors"
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/logging"
)

const (
	// Maximum reordering in time space before time based loss detection considers a packet lost.
	// Specified as an RTT multiplier.
	timeThreshold = 9.0 / 8
	// Maximum reordering in packets before packet threshold loss detection considers a packet lost.
	packetThreshold = 3
	// Before validating the client's address, the server won't send more than 3x bytes than it received.
	amplificationFactor = 3
	// We use Retry packets to derive an RTT estimate. Make sure we don't set the RTT to a super low value yet.
	minRTTAfterRetry = 5 * time.Millisecond
)

type ECNMode uint8

const (
	DisableECN ECNMode = 0x00
	// Enable ECN by sending packets marked as ECT(0)
	UseECT0 ECNMode = 0x01
	// Enable ECN by sending packets marked as ECT(1)
	UseECT1 ECNMode = 0x02
	// After successful ECN validation, deliberately send a CE-marked packet
	TryCE ECNMode = 0x04
)

func (m ECNMode) IsValid() bool {
	// At most one of UseECT{0,1} may be set
	return m&0x03 != 0x03
}

type ecnState int8

const (
	ecnCapable ecnState = -2
	ecnFailed  ecnState = -1
	ecnUnknown ecnState = 0
	// COMSYS zgrabber patch: RFC 9000 recommends 10 ECN validation packets,
	// but we only send half the number of PTO probes for initial packets
	ecnTesting ecnState = 5
)

func (s ecnState) IsValidating() bool {
	return s >= 0
}

type packetNumberSpace struct {
	history *sentPacketHistory
	pns     packetNumberGenerator

	lossTime                   time.Time
	lastAckElicitingPacketTime time.Time

	largestAcked protocol.PacketNumber
	largestSent  protocol.PacketNumber
	ect, ecnce   uint64 // from latest ACK
}

func newPacketNumberSpace(initialPN protocol.PacketNumber, skipPNs bool, rttStats *utils.RTTStats) *packetNumberSpace {
	var pns packetNumberGenerator
	if skipPNs {
		pns = newSkippingPacketNumberGenerator(initialPN, protocol.SkipPacketInitialPeriod, protocol.SkipPacketMaxPeriod)
	} else {
		pns = newSequentialPacketNumberGenerator(initialPN)
	}
	return &packetNumberSpace{
		history:      newSentPacketHistory(rttStats),
		pns:          pns,
		largestSent:  protocol.InvalidPacketNumber,
		largestAcked: protocol.InvalidPacketNumber,
	}
}

type sentPacketHandler struct {
	initialPackets   *packetNumberSpace
	handshakePackets *packetNumberSpace
	appDataPackets   *packetNumberSpace

	// Do we know that the peer completed address validation yet?
	// Always true for the server.
	peerCompletedAddressValidation bool
	bytesReceived                  protocol.ByteCount
	bytesSent                      protocol.ByteCount
	// Have we validated the peer's address yet?
	// Always true for the client.
	peerAddressValidated bool

	handshakeConfirmed bool

	// lowestNotConfirmedAcked is the lowest packet number that we sent an ACK for, but haven't received confirmation, that this ACK actually arrived
	// example: we send an ACK for packets 90-100 with packet number 20
	// once we receive an ACK from the peer for packet 20, the lowestNotConfirmedAcked is 101
	// Only applies to the application-data packet number space.
	lowestNotConfirmedAcked protocol.PacketNumber

	ackedPackets []*Packet // to avoid allocations in detectAndRemoveAckedPackets

	bytesInFlight protocol.ByteCount

	congestion congestion.SendAlgorithmWithDebugInfos
	rttStats   *utils.RTTStats

	// The number of times a PTO has been sent without receiving an ack.
	ptoCount uint32
	ptoMode  SendMode
	// The number of PTO probe packets that should be sent.
	// Only applies to the application-data packet number space.
	numProbesToSend int

	// If <= 0: fixed ECN state (capable, failed, or unknown)
	// If  > 0: number of packets to mark for ECN validation
	ecnState ecnState
	// The number of ECN validation packets marked lost.
	ecnLost uint8
	// The number of ECN validation packets reported as CE
	ecnCE uint8
	// The ECN codepoint to use on outgoing packets
	ecnCodepoint protocol.ECN
	// The number of packets to send marked CE after successful ECN validation
	ecnTryCE uint8

	// The alarm timeout
	alarm time.Time

	perspective protocol.Perspective

	tracer logging.ConnectionTracer
	logger utils.Logger
}

var (
	_ SentPacketHandler = &sentPacketHandler{}
	_ sentPacketTracker = &sentPacketHandler{}
)

func newSentPacketHandler(
	initialPN protocol.PacketNumber,
	initialMaxDatagramSize protocol.ByteCount,
	rttStats *utils.RTTStats,
	ecnMode ECNMode,
	pers protocol.Perspective,
	tracer logging.ConnectionTracer,
	logger utils.Logger,
) *sentPacketHandler {
	congestion := congestion.NewCubicSender(
		congestion.DefaultClock{},
		rttStats,
		initialMaxDatagramSize,
		true, // use Reno
		tracer,
	)

	ecnState := ecnFailed
	ecnCodepoint := protocol.ECNNon
	ecnTryCE := uint8(0)
	switch ecnMode & (UseECT0 | UseECT1) {
	case UseECT0:
		ecnState = ecnTesting
		ecnCodepoint = protocol.ECT0
	case UseECT1:
		ecnState = ecnTesting
		ecnCodepoint = protocol.ECT1
	}
	if ecnMode&TryCE != 0 {
		ecnTryCE = 2
	}

	return &sentPacketHandler{
		peerCompletedAddressValidation: pers == protocol.PerspectiveServer,
		peerAddressValidated:           pers == protocol.PerspectiveClient,
		initialPackets:                 newPacketNumberSpace(initialPN, false, rttStats),
		handshakePackets:               newPacketNumberSpace(0, false, rttStats),
		appDataPackets:                 newPacketNumberSpace(0, true, rttStats),
		rttStats:                       rttStats,
		congestion:                     congestion,
		ecnState:                       ecnState,
		ecnCodepoint:                   ecnCodepoint,
		ecnTryCE:                       ecnTryCE,
		perspective:                    pers,
		tracer:                         tracer,
		logger:                         logger,
	}
}

func (h *sentPacketHandler) DropPackets(encLevel protocol.EncryptionLevel) {
	if h.perspective == protocol.PerspectiveClient && encLevel == protocol.EncryptionInitial {
		// This function is called when the crypto setup seals a Handshake packet.
		// If this Handshake packet is coalesced behind an Initial packet, we would drop the Initial packet number space
		// before SentPacket() was called for that Initial packet.
		return
	}
	h.dropPackets(encLevel)
}

func (h *sentPacketHandler) removeFromBytesInFlight(p *Packet) {
	if p.includedInBytesInFlight {
		if p.Length > h.bytesInFlight {
			panic("negative bytes_in_flight")
		}
		h.bytesInFlight -= p.Length
		p.includedInBytesInFlight = false
	}
}

func (h *sentPacketHandler) dropPackets(encLevel protocol.EncryptionLevel) {
	// The server won't await address validation after the handshake is confirmed.
	// This applies even if we didn't receive an ACK for a Handshake packet.
	if h.perspective == protocol.PerspectiveClient && encLevel == protocol.EncryptionHandshake {
		h.peerCompletedAddressValidation = true
	}
	// remove outstanding packets from bytes_in_flight
	if encLevel == protocol.EncryptionInitial || encLevel == protocol.EncryptionHandshake {
		pnSpace := h.getPacketNumberSpace(encLevel)
		pnSpace.history.Iterate(func(p *Packet) (bool, error) {
			h.removeFromBytesInFlight(p)
			return true, nil
		})
	}
	// drop the packet history
	//nolint:exhaustive // Not every packet number space can be dropped.
	switch encLevel {
	case protocol.EncryptionInitial:
		h.initialPackets = nil
	case protocol.EncryptionHandshake:
		h.handshakePackets = nil
	case protocol.Encryption0RTT:
		// This function is only called when 0-RTT is rejected,
		// and not when the client drops 0-RTT keys when the handshake completes.
		// When 0-RTT is rejected, all application data sent so far becomes invalid.
		// Delete the packets from the history and remove them from bytes_in_flight.
		h.appDataPackets.history.Iterate(func(p *Packet) (bool, error) {
			if p.EncryptionLevel != protocol.Encryption0RTT {
				return false, nil
			}
			h.removeFromBytesInFlight(p)
			h.appDataPackets.history.Remove(p.PacketNumber)
			return true, nil
		})
	default:
		panic(fmt.Sprintf("Cannot drop keys for encryption level %s", encLevel))
	}
	if h.tracer != nil && h.ptoCount != 0 {
		h.tracer.UpdatedPTOCount(0)
	}
	h.ptoCount = 0
	h.numProbesToSend = 0
	h.ptoMode = SendNone
	h.setLossDetectionTimer()
}

func (h *sentPacketHandler) ReceivedBytes(n protocol.ByteCount) {
	wasAmplificationLimit := h.isAmplificationLimited()
	h.bytesReceived += n
	if wasAmplificationLimit && !h.isAmplificationLimited() {
		h.setLossDetectionTimer()
	}
}

func (h *sentPacketHandler) ReceivedPacket(l protocol.EncryptionLevel) {
	if h.perspective == protocol.PerspectiveServer && l == protocol.EncryptionHandshake && !h.peerAddressValidated {
		h.peerAddressValidated = true
		h.setLossDetectionTimer()
	}
}

func (h *sentPacketHandler) packetsInFlight() int {
	packetsInFlight := h.appDataPackets.history.Len()
	if h.handshakePackets != nil {
		packetsInFlight += h.handshakePackets.history.Len()
	}
	if h.initialPackets != nil {
		packetsInFlight += h.initialPackets.history.Len()
	}
	return packetsInFlight
}

func (h *sentPacketHandler) SentPacket(packet *Packet) {
	h.bytesSent += packet.Length
	// For the client, drop the Initial packet number space when the first Handshake packet is sent.
	if h.perspective == protocol.PerspectiveClient && packet.EncryptionLevel == protocol.EncryptionHandshake && h.initialPackets != nil {
		h.dropPackets(protocol.EncryptionInitial)
	}
	isAckEliciting := h.sentPacketImpl(packet)
	h.getPacketNumberSpace(packet.EncryptionLevel).history.SentPacket(packet, isAckEliciting)
	if h.tracer != nil && isAckEliciting {
		h.tracer.UpdatedMetrics(h.rttStats, h.congestion.GetCongestionWindow(), h.bytesInFlight, h.packetsInFlight())
	}
	if isAckEliciting || !h.peerCompletedAddressValidation {
		h.setLossDetectionTimer()
	}
}

func (h *sentPacketHandler) getPacketNumberSpace(encLevel protocol.EncryptionLevel) *packetNumberSpace {
	switch encLevel {
	case protocol.EncryptionInitial:
		return h.initialPackets
	case protocol.EncryptionHandshake:
		return h.handshakePackets
	case protocol.Encryption0RTT, protocol.Encryption1RTT:
		return h.appDataPackets
	default:
		panic("invalid packet number space")
	}
}

func (h *sentPacketHandler) sentPacketImpl(packet *Packet) bool /* is ack-eliciting */ {
	pnSpace := h.getPacketNumberSpace(packet.EncryptionLevel)

	if h.logger.Debug() && pnSpace.history.HasOutstandingPackets() {
		for p := utils.MaxPacketNumber(0, pnSpace.largestSent+1); p < packet.PacketNumber; p++ {
			h.logger.Debugf("Skipping packet number %d", p)
		}
	}

	pnSpace.largestSent = packet.PacketNumber
	isAckEliciting := len(packet.Frames) > 0

	if isAckEliciting {
		pnSpace.lastAckElicitingPacketTime = packet.SendTime
		packet.includedInBytesInFlight = true
		h.bytesInFlight += packet.Length
		if h.numProbesToSend > 0 {
			h.numProbesToSend--
		}
	}
	h.congestion.OnPacketSent(packet.SendTime, h.bytesInFlight, packet.PacketNumber, packet.Length, isAckEliciting)

	return isAckEliciting
}

func (h *sentPacketHandler) ReceivedAck(ack *wire.AckFrame, encLevel protocol.EncryptionLevel, rcvTime time.Time) (bool /* contained 1-RTT packet */, error) {
	pnSpace := h.getPacketNumberSpace(encLevel)

	largestAcked := ack.LargestAcked()
	if largestAcked > pnSpace.largestSent {
		return false, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received ACK for an unsent packet",
		}
	}

	largestAckedIncreased := largestAcked > pnSpace.largestAcked
	if largestAckedIncreased {
		pnSpace.largestAcked = largestAcked
	}

	// Servers complete address validation when a protected packet is received.
	if h.perspective == protocol.PerspectiveClient && !h.peerCompletedAddressValidation &&
		(encLevel == protocol.EncryptionHandshake || encLevel == protocol.Encryption1RTT) {
		h.peerCompletedAddressValidation = true
		h.logger.Debugf("Peer doesn't await address validation any longer.")
		// Make sure that the timer is reset, even if this ACK doesn't acknowledge any (ack-eliciting) packets.
		h.setLossDetectionTimer()
	}

	priorInFlight := h.bytesInFlight
	ackedPackets, err := h.detectAndRemoveAckedPackets(ack, encLevel)
	if err != nil || len(ackedPackets) == 0 {
		return false, err
	}
	// update the RTT, if the largest acked is newly acknowledged
	if p := ackedPackets[len(ackedPackets)-1]; p.PacketNumber == largestAcked {
		// don't use the ack delay for Initial and Handshake packets
		var ackDelay time.Duration
		if encLevel == protocol.Encryption1RTT {
			ackDelay = utils.MinDuration(ack.DelayTime, h.rttStats.MaxAckDelay())
		}
		h.rttStats.UpdateRTT(rcvTime.Sub(p.SendTime), ackDelay, rcvTime)
		if h.logger.Debug() {
			h.logger.Debugf("\tupdated RTT: %s (σ: %s)", h.rttStats.SmoothedRTT(), h.rttStats.MeanDeviation())
		}
		h.congestion.MaybeExitSlowStart()
	}
	if err := h.detectLostPackets(rcvTime, encLevel); err != nil {
		return false, err
	}
	if h.ecnState != ecnFailed {
		h.processECNCounts(ack, encLevel, largestAckedIncreased, ackedPackets)
	}
	var acked1RTTPacket bool
	for _, p := range ackedPackets {
		if p.includedInBytesInFlight && !p.declaredLost {
			h.congestion.OnPacketAcked(p.PacketNumber, p.Length, priorInFlight, rcvTime)
		}
		if p.EncryptionLevel == protocol.Encryption1RTT {
			acked1RTTPacket = true
		}
		h.removeFromBytesInFlight(p)
	}

	// Reset the pto_count unless the client is unsure if the server has validated the client's address.
	if h.peerCompletedAddressValidation {
		if h.tracer != nil && h.ptoCount != 0 {
			h.tracer.UpdatedPTOCount(0)
		}
		h.ptoCount = 0
	}
	h.numProbesToSend = 0

	if h.tracer != nil {
		h.tracer.UpdatedMetrics(h.rttStats, h.congestion.GetCongestionWindow(), h.bytesInFlight, h.packetsInFlight())
	}

	pnSpace.history.DeleteOldPackets(rcvTime)
	h.setLossDetectionTimer()
	return acked1RTTPacket, nil
}

func (h *sentPacketHandler) GetLowestPacketNotConfirmedAcked() protocol.PacketNumber {
	return h.lowestNotConfirmedAcked
}

// Packets are returned in ascending packet number order.
func (h *sentPacketHandler) detectAndRemoveAckedPackets(ack *wire.AckFrame, encLevel protocol.EncryptionLevel) ([]*Packet, error) {
	pnSpace := h.getPacketNumberSpace(encLevel)
	h.ackedPackets = h.ackedPackets[:0]
	ackRangeIndex := 0
	lowestAcked := ack.LowestAcked()
	largestAcked := ack.LargestAcked()
	err := pnSpace.history.Iterate(func(p *Packet) (bool, error) {
		// Ignore packets below the lowest acked
		if p.PacketNumber < lowestAcked {
			return true, nil
		}
		// Break after largest acked is reached
		if p.PacketNumber > largestAcked {
			return false, nil
		}

		if ack.HasMissingRanges() {
			ackRange := ack.AckRanges[len(ack.AckRanges)-1-ackRangeIndex]

			for p.PacketNumber > ackRange.Largest && ackRangeIndex < len(ack.AckRanges)-1 {
				ackRangeIndex++
				ackRange = ack.AckRanges[len(ack.AckRanges)-1-ackRangeIndex]
			}

			if p.PacketNumber < ackRange.Smallest { // packet not contained in ACK range
				return true, nil
			}
			if p.PacketNumber > ackRange.Largest {
				return false, fmt.Errorf("BUG: ackhandler would have acked wrong packet %d, while evaluating range %d -> %d", p.PacketNumber, ackRange.Smallest, ackRange.Largest)
			}
		}
		if p.skippedPacket {
			return false, &qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				ErrorMessage: fmt.Sprintf("received an ACK for skipped packet number: %d (%s)", p.PacketNumber, encLevel),
			}
		}
		h.ackedPackets = append(h.ackedPackets, p)
		return true, nil
	})
	if h.logger.Debug() && len(h.ackedPackets) > 0 {
		pns := make([]protocol.PacketNumber, len(h.ackedPackets))
		for i, p := range h.ackedPackets {
			pns[i] = p.PacketNumber
		}
		h.logger.Debugf("\tnewly acked packets (%d): %d", len(pns), pns)
	}

	for _, p := range h.ackedPackets {
		if p.LargestAcked != protocol.InvalidPacketNumber && encLevel == protocol.Encryption1RTT {
			h.lowestNotConfirmedAcked = utils.MaxPacketNumber(h.lowestNotConfirmedAcked, p.LargestAcked+1)
		}

		for _, f := range p.Frames {
			if f.OnAcked != nil {
				f.OnAcked(f.Frame)
			}
		}
		if err := pnSpace.history.Remove(p.PacketNumber); err != nil {
			return nil, err
		}
		if h.tracer != nil {
			h.tracer.AcknowledgedPacket(encLevel, p.PacketNumber)
		}
	}

	return h.ackedPackets, err
}

func (h *sentPacketHandler) processECNCounts(ack *wire.AckFrame, encLevel protocol.EncryptionLevel, largestAckedIncreased bool, ackedPackets []*Packet) {
	sentCP := h.ecnCodepoint
	unusedCP := sentCP ^ 0b11 // 0b10 <-> 0b01
	var ackECT, ackUnused uint64
	switch sentCP {
	case protocol.ECT0:
		ackECT = ack.ECT0
		ackUnused = ack.ECT1
	case protocol.ECT1:
		ackECT = ack.ECT1
		ackUnused = ack.ECT0
	default:
		panic(fmt.Sprintf("default ECN codepoint is %#b", sentCP))
	}

	pnSpace := h.getPacketNumberSpace(encLevel)
	var ect, ecnce uint64
	lost := ackedPackets[len(ackedPackets)-1] // packet to potentially pass to congestion.OnPacketLost()
	for _, p := range ackedPackets {
		switch p.TOS.ECN() {
		case sentCP:
			ect++
			lost = p // use last marked packet, if any
		case protocol.ECNCE:
			ecnce++
			lost = p // use last marked packet, if any
		case unusedCP:
			h.logger.Errorf(
				"BUG: unexpected ECT(%d) packet with pn %d (%s)",
				unusedCP&1, p.PacketNumber, p.EncryptionLevel,
			)
		}
	}

	if largestAckedIncreased {
		// Perform ECN validation
		if !ack.HasECN() {
			if ect > 0 || ecnce > 0 {
				h.updateECNState(ecnFailed, logging.ECNValidationMissingCounters)
				return
			}
			return // nothing to validate/process
		}
		if ackECT < pnSpace.ect {
			result := logging.ECNValidationDecreasingECT0
			if sentCP == protocol.ECT1 {
				result = logging.ECNValidationDecreasingECT1
			}
			h.updateECNState(ecnFailed, result)
			return
		}
		if ack.ECNCE < pnSpace.ecnce {
			h.updateECNState(ecnFailed, logging.ECNValidationDecreasingCE)
			return
		}
		if ackUnused > 0 {
			// h.GetTOS() never sets the unused ECN codepoint
			reason := logging.ECNValidationIllegalECT1
			if sentCP == protocol.ECT1 {
				reason = logging.ECNValidationIllegalECT0
			}
			h.updateECNState(ecnFailed, reason)
			return
		}

		deltaCE := ack.ECNCE - pnSpace.ecnce
		if ecnce > deltaCE {
			h.updateECNState(ecnFailed, logging.ECNValidationMissingCE)
			return
		}
		deltaECT := (ackECT - pnSpace.ect) + (deltaCE - ecnce) // ECT may be re-marked to CE
		if ect > deltaECT {
			reason := logging.ECNValidationMissingECT0
			if sentCP == protocol.ECT1 {
				reason = logging.ECNValidationMissingECT1
			}
			h.updateECNState(ecnFailed, reason)
			return
		}

		h.logger.Debugf("\tECN validation passed")
		if h.ecnState.IsValidating() && ackECT > 0 {
			// The validation stage can only be left after at least one non-CE echo
			// has been received. Otherwise, validation could still fail due to all-CE.
			h.updateECNState(ecnCapable, logging.ECNValidationSuccess)
		}
	}

	// The local CE count needs to be compensated for ACKed packets that were
	// originally sent with a CE mark. Otherwise, ACKs could mistakenly triger
	// a congestion response because their CE count includes these packets.
	pnSpace.ecnce += ecnce

	// If ack doesn't contain ECN counts (ack.EC* == 0), these will always be false
	if ack.ECNCE > pnSpace.ecnce {
		if h.ecnState.IsValidating() {
			h.ecnCE += uint8(ack.ECNCE - pnSpace.ecnce) // over-counts on coalesced packets
			if h.ecnCE >= uint8(ecnTesting) {
				h.updateECNState(ecnFailed, logging.ECNValidationAllCE)
				return
			}
		}
		lost.declaredLost = true // to circumvent congestion.OnPacketAcked() call in h.ReceivedAck()
		h.congestion.OnPacketLost(lost.PacketNumber, lost.Length, h.bytesInFlight)
		pnSpace.ecnce = ack.ECNCE
	}
	if ackECT > pnSpace.ect {
		pnSpace.ect = ackECT
	}
}

func (h *sentPacketHandler) updateECNState(newState ecnState, result logging.ECNValidationResult) {
	h.ecnState = newState
	if h.tracer != nil {
		h.tracer.ValidatedECN(result)
	}
	h.logger.Debugf("ECN validation updated: %s", result)
}

func (h *sentPacketHandler) getLossTimeAndSpace() (time.Time, protocol.EncryptionLevel) {
	var encLevel protocol.EncryptionLevel
	var lossTime time.Time

	if h.initialPackets != nil {
		lossTime = h.initialPackets.lossTime
		encLevel = protocol.EncryptionInitial
	}
	if h.handshakePackets != nil && (lossTime.IsZero() || (!h.handshakePackets.lossTime.IsZero() && h.handshakePackets.lossTime.Before(lossTime))) {
		lossTime = h.handshakePackets.lossTime
		encLevel = protocol.EncryptionHandshake
	}
	if lossTime.IsZero() || (!h.appDataPackets.lossTime.IsZero() && h.appDataPackets.lossTime.Before(lossTime)) {
		lossTime = h.appDataPackets.lossTime
		encLevel = protocol.Encryption1RTT
	}
	return lossTime, encLevel
}

// same logic as getLossTimeAndSpace, but for lastAckElicitingPacketTime instead of lossTime
func (h *sentPacketHandler) getPTOTimeAndSpace() (pto time.Time, encLevel protocol.EncryptionLevel, ok bool) {
	// We only send application data probe packets once the handshake is confirmed,
	// because before that, we don't have the keys to decrypt ACKs sent in 1-RTT packets.
	if !h.handshakeConfirmed && !h.hasOutstandingCryptoPackets() {
		if h.peerCompletedAddressValidation {
			return
		}
		t := time.Now().Add(h.rttStats.PTO(false) << h.ptoCount)
		if h.initialPackets != nil {
			return t, protocol.EncryptionInitial, true
		}
		return t, protocol.EncryptionHandshake, true
	}

	if h.initialPackets != nil {
		encLevel = protocol.EncryptionInitial
		if t := h.initialPackets.lastAckElicitingPacketTime; !t.IsZero() {
			pto = t.Add(h.rttStats.PTO(false) << h.ptoCount)
		}
	}
	if h.handshakePackets != nil && !h.handshakePackets.lastAckElicitingPacketTime.IsZero() {
		t := h.handshakePackets.lastAckElicitingPacketTime.Add(h.rttStats.PTO(false) << h.ptoCount)
		if pto.IsZero() || (!t.IsZero() && t.Before(pto)) {
			pto = t
			encLevel = protocol.EncryptionHandshake
		}
	}
	if h.handshakeConfirmed && !h.appDataPackets.lastAckElicitingPacketTime.IsZero() {
		t := h.appDataPackets.lastAckElicitingPacketTime.Add(h.rttStats.PTO(true) << h.ptoCount)
		if pto.IsZero() || (!t.IsZero() && t.Before(pto)) {
			pto = t
			encLevel = protocol.Encryption1RTT
		}
	}
	return pto, encLevel, true
}

func (h *sentPacketHandler) hasOutstandingCryptoPackets() bool {
	var hasInitial, hasHandshake bool
	if h.initialPackets != nil {
		hasInitial = h.initialPackets.history.HasOutstandingPackets()
	}
	if h.handshakePackets != nil {
		hasHandshake = h.handshakePackets.history.HasOutstandingPackets()
	}
	return hasInitial || hasHandshake
}

func (h *sentPacketHandler) hasOutstandingPackets() bool {
	return h.appDataPackets.history.HasOutstandingPackets() || h.hasOutstandingCryptoPackets()
}

func (h *sentPacketHandler) setLossDetectionTimer() {
	oldAlarm := h.alarm // only needed in case tracing is enabled
	lossTime, encLevel := h.getLossTimeAndSpace()
	if !lossTime.IsZero() {
		// Early retransmit timer or time loss detection.
		h.alarm = lossTime
		if h.tracer != nil && h.alarm != oldAlarm {
			h.tracer.SetLossTimer(logging.TimerTypeACK, encLevel, h.alarm)
		}
		return
	}

	// Cancel the alarm if amplification limited.
	if h.isAmplificationLimited() {
		h.alarm = time.Time{}
		if !oldAlarm.IsZero() {
			h.logger.Debugf("Canceling loss detection timer. Amplification limited.")
			if h.tracer != nil {
				h.tracer.LossTimerCanceled()
			}
		}
		return
	}

	// Cancel the alarm if no packets are outstanding
	if !h.hasOutstandingPackets() && h.peerCompletedAddressValidation {
		h.alarm = time.Time{}
		if !oldAlarm.IsZero() {
			h.logger.Debugf("Canceling loss detection timer. No packets in flight.")
			if h.tracer != nil {
				h.tracer.LossTimerCanceled()
			}
		}
		return
	}

	// PTO alarm
	ptoTime, encLevel, ok := h.getPTOTimeAndSpace()
	if !ok {
		return
	}
	h.alarm = ptoTime
	if h.tracer != nil && h.alarm != oldAlarm {
		h.tracer.SetLossTimer(logging.TimerTypePTO, encLevel, h.alarm)
	}
}

func (h *sentPacketHandler) detectLostPackets(now time.Time, encLevel protocol.EncryptionLevel) error {
	pnSpace := h.getPacketNumberSpace(encLevel)
	pnSpace.lossTime = time.Time{}

	maxRTT := float64(utils.MaxDuration(h.rttStats.LatestRTT(), h.rttStats.SmoothedRTT()))
	lossDelay := time.Duration(timeThreshold * maxRTT)

	// Minimum time of granularity before packets are deemed lost.
	lossDelay = utils.MaxDuration(lossDelay, protocol.TimerGranularity)

	// Packets sent before this time are deemed lost.
	lostSendTime := now.Add(-lossDelay)

	priorInFlight := h.bytesInFlight
	return pnSpace.history.Iterate(func(p *Packet) (bool, error) {
		if p.PacketNumber > pnSpace.largestAcked {
			return false, nil
		}
		if p.declaredLost || p.skippedPacket {
			return true, nil
		}

		var packetLost bool
		if p.SendTime.Before(lostSendTime) {
			packetLost = true
			if h.logger.Debug() {
				h.logger.Debugf("\tlost packet %d (time threshold)", p.PacketNumber)
			}
			if h.tracer != nil {
				h.tracer.LostPacket(p.EncryptionLevel, p.PacketNumber, logging.PacketLossTimeThreshold)
			}
		} else if pnSpace.largestAcked >= p.PacketNumber+packetThreshold {
			packetLost = true
			if h.logger.Debug() {
				h.logger.Debugf("\tlost packet %d (reordering threshold)", p.PacketNumber)
			}
			if h.tracer != nil {
				h.tracer.LostPacket(p.EncryptionLevel, p.PacketNumber, logging.PacketLossReorderingThreshold)
			}
		} else if pnSpace.lossTime.IsZero() {
			// Note: This conditional is only entered once per call
			lossTime := p.SendTime.Add(lossDelay)
			if h.logger.Debug() {
				h.logger.Debugf("\tsetting loss timer for packet %d (%s) to %s (in %s)", p.PacketNumber, encLevel, lossDelay, lossTime)
			}
			pnSpace.lossTime = lossTime
		}
		if packetLost {
			p.declaredLost = true
			// the bytes in flight need to be reduced no matter if the frames in this packet will be retransmitted
			h.removeFromBytesInFlight(p)
			h.queueFramesForRetransmission(p)
			h.checkECNValidationLoss(p)
			if !p.IsPathMTUProbePacket {
				h.congestion.OnPacketLost(p.PacketNumber, p.Length, priorInFlight)
			}
		}
		return true, nil
	})
}

func (h *sentPacketHandler) checkECNValidationLoss(p *Packet) {
	if !h.ecnState.IsValidating() || p.TOS.ECN() == protocol.ECNNon {
		return
	}
	h.ecnLost++ // over-counts on coalesced packets
	if h.ecnLost >= uint8(ecnTesting) {
		h.updateECNState(ecnFailed, logging.ECNValidationAllLost)
	}
}

func (h *sentPacketHandler) OnLossDetectionTimeout() error {
	defer h.setLossDetectionTimer()
	earliestLossTime, encLevel := h.getLossTimeAndSpace()
	if !earliestLossTime.IsZero() {
		if h.logger.Debug() {
			h.logger.Debugf("Loss detection alarm fired in loss timer mode. Loss time: %s", earliestLossTime)
		}
		if h.tracer != nil {
			h.tracer.LossTimerExpired(logging.TimerTypeACK, encLevel)
		}
		// Early retransmit or time loss detection
		return h.detectLostPackets(time.Now(), encLevel)
	}

	// PTO
	// When all outstanding are acknowledged, the alarm is canceled in
	// setLossDetectionTimer. This doesn't reset the timer in the session though.
	// When OnAlarm is called, we therefore need to make sure that there are
	// actually packets outstanding.
	if h.bytesInFlight == 0 && !h.peerCompletedAddressValidation {
		h.ptoCount++
		h.numProbesToSend++
		if h.initialPackets != nil {
			h.ptoMode = SendPTOInitial
		} else if h.handshakePackets != nil {
			h.ptoMode = SendPTOHandshake
		} else {
			return errors.New("sentPacketHandler BUG: PTO fired, but bytes_in_flight is 0 and Initial and Handshake already dropped")
		}
		return nil
	}

	_, encLevel, ok := h.getPTOTimeAndSpace()
	if !ok {
		return nil
	}
	if ps := h.getPacketNumberSpace(encLevel); !ps.history.HasOutstandingPackets() && !h.peerCompletedAddressValidation {
		return nil
	}
	h.ptoCount++
	if h.logger.Debug() {
		h.logger.Debugf("Loss detection alarm for %s fired in PTO mode. PTO count: %d", encLevel, h.ptoCount)
	}
	if h.tracer != nil {
		h.tracer.LossTimerExpired(logging.TimerTypePTO, encLevel)
		h.tracer.UpdatedPTOCount(h.ptoCount)
	}
	h.numProbesToSend += 2
	//nolint:exhaustive // We never arm a PTO timer for 0-RTT packets.
	switch encLevel {
	case protocol.EncryptionInitial:
		//COMSYS zgrabber patch: do not resend two initial probes, but only a single one to avoid annoying people
		h.numProbesToSend -= 1
		h.ptoMode = SendPTOInitial
	case protocol.EncryptionHandshake:
		h.ptoMode = SendPTOHandshake
	case protocol.Encryption1RTT:
		// skip a packet number in order to elicit an immediate ACK
		_ = h.PopPacketNumber(protocol.Encryption1RTT)
		h.ptoMode = SendPTOAppData
	default:
		return fmt.Errorf("PTO timer in unexpected encryption level: %s", encLevel)
	}
	return nil
}

func (h *sentPacketHandler) GetLossDetectionTimeout() time.Time {
	return h.alarm
}

func (h *sentPacketHandler) PeekPacketNumber(encLevel protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
	pnSpace := h.getPacketNumberSpace(encLevel)

	var lowestUnacked protocol.PacketNumber
	if p := pnSpace.history.FirstOutstanding(); p != nil {
		lowestUnacked = p.PacketNumber
	} else {
		lowestUnacked = pnSpace.largestAcked + 1
	}

	pn := pnSpace.pns.Peek()
	return pn, protocol.GetPacketNumberLengthForHeader(pn, lowestUnacked)
}

func (h *sentPacketHandler) PopPacketNumber(encLevel protocol.EncryptionLevel) protocol.PacketNumber {
	return h.getPacketNumberSpace(encLevel).pns.Pop()
}

func (h *sentPacketHandler) GetTOS(isAckEliciting bool) protocol.TOS {
	switch h.ecnState {
	case ecnCapable:
		if h.ecnTryCE > 0 {
			h.ecnTryCE--
			return protocol.ECNCE.ToTOS()
		}
		return h.ecnCodepoint.ToTOS()
	case ecnFailed, ecnUnknown:
		return protocol.TOSDefault
	}
	if h.ecnState <= 0 {
		panic("invalid ecnState")
	}

	// Attempt ECN validation according to RFC 9000, appendix A.4
	if !isAckEliciting {
		// Non-ack-eliciting packets aren't tracked by sentPacketHandler, thus
		// losses will never be noticed. This means they aren't suitable for ECN validation.
		return protocol.TOSDefault
	}
	h.ecnState-- // reduce outstanding validation packets
	return h.ecnCodepoint.ToTOS()
}

func (h *sentPacketHandler) SendMode() SendMode {
	numTrackedPackets := h.appDataPackets.history.Len()
	if h.initialPackets != nil {
		numTrackedPackets += h.initialPackets.history.Len()
	}
	if h.handshakePackets != nil {
		numTrackedPackets += h.handshakePackets.history.Len()
	}

	if h.isAmplificationLimited() {
		h.logger.Debugf("Amplification window limited. Received %d bytes, already sent out %d bytes", h.bytesReceived, h.bytesSent)
		return SendNone
	}
	// Don't send any packets if we're keeping track of the maximum number of packets.
	// Note that since MaxOutstandingSentPackets is smaller than MaxTrackedSentPackets,
	// we will stop sending out new data when reaching MaxOutstandingSentPackets,
	// but still allow sending of retransmissions and ACKs.
	if numTrackedPackets >= protocol.MaxTrackedSentPackets {
		if h.logger.Debug() {
			h.logger.Debugf("Limited by the number of tracked packets: tracking %d packets, maximum %d", numTrackedPackets, protocol.MaxTrackedSentPackets)
		}
		return SendNone
	}
	if h.numProbesToSend > 0 {
		return h.ptoMode
	}
	// Only send ACKs if we're congestion limited.
	if !h.congestion.CanSend(h.bytesInFlight) {
		if h.logger.Debug() {
			h.logger.Debugf("Congestion limited: bytes in flight %d, window %d", h.bytesInFlight, h.congestion.GetCongestionWindow())
		}
		return SendAck
	}
	if numTrackedPackets >= protocol.MaxOutstandingSentPackets {
		if h.logger.Debug() {
			h.logger.Debugf("Max outstanding limited: tracking %d packets, maximum: %d", numTrackedPackets, protocol.MaxOutstandingSentPackets)
		}
		return SendAck
	}
	return SendAny
}

func (h *sentPacketHandler) TimeUntilSend() time.Time {
	return h.congestion.TimeUntilSend(h.bytesInFlight)
}

func (h *sentPacketHandler) HasPacingBudget() bool {
	return h.congestion.HasPacingBudget()
}

func (h *sentPacketHandler) SetMaxDatagramSize(s protocol.ByteCount) {
	h.congestion.SetMaxDatagramSize(s)
}

func (h *sentPacketHandler) isAmplificationLimited() bool {
	if h.peerAddressValidated {
		return false
	}
	return h.bytesSent >= amplificationFactor*h.bytesReceived
}

func (h *sentPacketHandler) QueueProbePacket(encLevel protocol.EncryptionLevel) bool {
	pnSpace := h.getPacketNumberSpace(encLevel)
	p := pnSpace.history.FirstOutstanding()
	if p == nil {
		return false
	}
	h.queueFramesForRetransmission(p)
	// TODO: don't declare the packet lost here.
	// Keep track of acknowledged frames instead.
	h.removeFromBytesInFlight(p)
	p.declaredLost = true
	h.checkECNValidationLoss(p)
	return true
}

func (h *sentPacketHandler) queueFramesForRetransmission(p *Packet) {
	if len(p.Frames) == 0 {
		panic("no frames")
	}
	for _, f := range p.Frames {
		f.OnLost(f.Frame)
	}
	p.Frames = nil
}

func (h *sentPacketHandler) ResetForRetry() error {
	h.bytesInFlight = 0
	var firstPacketSendTime time.Time
	h.initialPackets.history.Iterate(func(p *Packet) (bool, error) {
		if firstPacketSendTime.IsZero() {
			firstPacketSendTime = p.SendTime
		}
		if p.declaredLost || p.skippedPacket {
			return true, nil
		}
		h.queueFramesForRetransmission(p)
		return true, nil
	})
	// All application data packets sent at this point are 0-RTT packets.
	// In the case of a Retry, we can assume that the server dropped all of them.
	h.appDataPackets.history.Iterate(func(p *Packet) (bool, error) {
		if !p.declaredLost && !p.skippedPacket {
			h.queueFramesForRetransmission(p)
		}
		return true, nil
	})

	// Only use the Retry to estimate the RTT if we didn't send any retransmission for the Initial.
	// Otherwise, we don't know which Initial the Retry was sent in response to.
	if h.ptoCount == 0 {
		// Don't set the RTT to a value lower than 5ms here.
		now := time.Now()
		h.rttStats.UpdateRTT(utils.MaxDuration(minRTTAfterRetry, now.Sub(firstPacketSendTime)), 0, now)
		if h.logger.Debug() {
			h.logger.Debugf("\tupdated RTT: %s (σ: %s)", h.rttStats.SmoothedRTT(), h.rttStats.MeanDeviation())
		}
		if h.tracer != nil {
			h.tracer.UpdatedMetrics(h.rttStats, h.congestion.GetCongestionWindow(), h.bytesInFlight, h.packetsInFlight())
		}
	}
	h.initialPackets = newPacketNumberSpace(h.initialPackets.pns.Pop(), false, h.rttStats)
	h.appDataPackets = newPacketNumberSpace(h.appDataPackets.pns.Pop(), true, h.rttStats)
	if h.ecnState.IsValidating() {
		h.ecnState = ecnTesting
		h.ecnLost = 0
		h.ecnCE = 0
	}
	oldAlarm := h.alarm
	h.alarm = time.Time{}
	if h.tracer != nil {
		h.tracer.UpdatedPTOCount(0)
		if !oldAlarm.IsZero() {
			h.tracer.LossTimerCanceled()
		}
	}
	h.ptoCount = 0
	return nil
}

func (h *sentPacketHandler) SetHandshakeConfirmed() {
	h.handshakeConfirmed = true
	// We don't send PTOs for application data packets before the handshake completes.
	// Make sure the timer is armed now, if necessary.
	h.setLossDetectionTimer()
}
