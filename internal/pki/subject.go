package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
)

// oidEmailAddress is the legacy emailAddress RDN (1.2.840.113549.1.9.1). Go's
// pkix.Name has no field for it, so it is carried in ExtraNames.
var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// Subject is the flattened distinguished name Certio exposes over the API and
// stores as subject_json. One value per RDN keeps the forms and the JSON
// simple; multi-valued RDNs are rare enough to leave to the import path.
type Subject struct {
	CommonName         string `json:"common_name"`
	Country            string `json:"country,omitempty"`
	Province           string `json:"province,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Email              string `json:"email,omitempty"`
	SerialNumber       string `json:"serial_number,omitempty"`
}

// Validate rejects a subject that cannot produce a usable certificate.
func (s Subject) Validate() error {
	if strings.TrimSpace(s.CommonName) == "" {
		return fmt.Errorf("pki: subject common name is required")
	}
	if len(s.CommonName) > 64 {
		return fmt.Errorf("pki: common name exceeds the 64-character limit")
	}
	if s.Country != "" && len(s.Country) != 2 {
		return fmt.Errorf("pki: country must be a 2-letter ISO 3166 code, got %q", s.Country)
	}
	return nil
}

// Normalize trims whitespace and upper-cases the country code.
func (s Subject) Normalize() Subject {
	s.CommonName = strings.TrimSpace(s.CommonName)
	s.Country = strings.ToUpper(strings.TrimSpace(s.Country))
	s.Province = strings.TrimSpace(s.Province)
	s.Locality = strings.TrimSpace(s.Locality)
	s.Organization = strings.TrimSpace(s.Organization)
	s.OrganizationalUnit = strings.TrimSpace(s.OrganizationalUnit)
	s.Email = strings.TrimSpace(s.Email)
	return s
}

// ToPKIX converts the subject to the form crypto/x509 signs.
func (s Subject) ToPKIX() pkix.Name {
	name := pkix.Name{CommonName: s.CommonName, SerialNumber: s.SerialNumber}
	appendIfSet(&name.Country, s.Country)
	appendIfSet(&name.Province, s.Province)
	appendIfSet(&name.Locality, s.Locality)
	appendIfSet(&name.Organization, s.Organization)
	appendIfSet(&name.OrganizationalUnit, s.OrganizationalUnit)
	if s.Email != "" {
		name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidEmailAddress, Value: s.Email,
		})
	}
	return name
}

func appendIfSet(dst *[]string, value string) {
	if value != "" {
		*dst = append(*dst, value)
	}
}

// SubjectFromPKIX flattens a parsed distinguished name, taking the first value
// of each multi-valued RDN.
func SubjectFromPKIX(name pkix.Name) Subject {
	s := Subject{
		CommonName:         name.CommonName,
		Country:            first(name.Country),
		Province:           first(name.Province),
		Locality:           first(name.Locality),
		Organization:       first(name.Organization),
		OrganizationalUnit: first(name.OrganizationalUnit),
		SerialNumber:       name.SerialNumber,
	}
	for _, atv := range append(append([]pkix.AttributeTypeAndValue{}, name.Names...), name.ExtraNames...) {
		if atv.Type.Equal(oidEmailAddress) {
			if v, ok := atv.Value.(string); ok {
				s.Email = v
			}
		}
	}
	return s
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// DN renders the subject in the slash-separated form openssl's -subj expects,
// so the UI can show the equivalent command.
func (s Subject) DN() string {
	var b strings.Builder
	write := func(key, value string) {
		if value != "" {
			b.WriteString("/" + key + "=" + value)
		}
	}
	write("C", s.Country)
	write("ST", s.Province)
	write("L", s.Locality)
	write("O", s.Organization)
	write("OU", s.OrganizationalUnit)
	write("CN", s.CommonName)
	write("emailAddress", s.Email)
	if b.Len() == 0 {
		return "/"
	}
	return b.String()
}
