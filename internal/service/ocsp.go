package service

import (
	"errors"
	"fmt"
	"time"

	"github.com/jkaninda/certio/internal/pki"
	"github.com/jkaninda/certio/internal/store"
)

// ErrOCSPUnauthorized means the request asked a CA that is not this one, or
// one whose key Certio cannot use. The handler turns it into RFC 6960's
// unsigned "unauthorized" response rather than an HTTP error, because an OCSP
// client speaks OCSP and not JSON.
var ErrOCSPUnauthorized = errors.New("the responder cannot answer for this issuer")

// ocspValidity is how long a client may cache an answer. It is deliberately
// shorter than a CRL's lifetime: the point of OCSP over a CRL is freshness,
// and a day-old "good" for a key compromised this morning is the failure mode
// worth avoiding.
const ocspValidity = 1 * time.Hour

// OCSPRespond answers a status query for one CA.
//
// The answer is derived from the revocations table rather than from the
// published CRL, so a certificate revoked thirty seconds ago reports revoked
// immediately instead of waiting for the next CRL refresh.
func (s *Service) OCSPRespond(authorityID string, der []byte) ([]byte, error) {
	req, err := pki.ParseOCSPRequest(der)
	if err != nil {
		return nil, validationError("%s", err)
	}

	row, err := s.Store.Authorities.Resolve(authorityID)
	if err != nil {
		return nil, err
	}
	// A passphrase-protected CA cannot sign unattended, and an OCSP request
	// arrives with no operator behind it to supply one.
	if row.PassphraseProtected {
		return nil, fmt.Errorf("%w: CA %q needs a passphrase to sign", ErrOCSPUnauthorized, row.Name)
	}

	ca, err := s.LoadCA(row, "")
	if err != nil {
		return nil, err
	}
	if !req.MatchesIssuer(ca.Certificate) {
		return nil, fmt.Errorf("%w: the request names a different issuer", ErrOCSPUnauthorized)
	}

	serial := pki.FormatSerial(req.SerialNumber)
	now := time.Now()
	resp := pki.OCSPResponse{
		SerialNumber: req.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(ocspValidity),
		IssuerHash:   req.HashAlgorithm,
	}

	cert, err := s.Store.Certificates.GetBySerial(row.ID, serial)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// RFC 6960 §2.2 lets a responder answer "unknown" for a serial it has
		// no record of. Saying "good" instead would vouch for a certificate
		// this CA may never have issued.
		resp.Status = pki.OCSPUnknown
	case err != nil:
		return nil, err
	default:
		resp.Status = pki.OCSPGood
		if rev, revErr := s.Store.Revocations.ByCertificate(cert.ID); revErr == nil && rev != nil {
			resp.Status = pki.OCSPRevoked
			resp.RevokedAt = rev.RevokedAt
			resp.ReasonCode = rev.ReasonCode
		} else if revErr != nil && !errors.Is(revErr, store.ErrNotFound) {
			return nil, revErr
		}
	}

	return pki.SignOCSPResponse(ca, resp)
}
