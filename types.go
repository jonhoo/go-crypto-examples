package keys

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

// As defined in RFC5280
type SubjectPublicKeyInfo struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

// https://html.spec.whatwg.org/multipage/forms.html#publickeyandchallenge
type PublicKeyAndChallenge struct {
	Spki      SubjectPublicKeyInfo
	Challenge string
}

// https://html.spec.whatwg.org/multipage/forms.html#signedpublickeyandchallenge
type SignedPublicKeyAndChallenge struct {
	PublicKeyAndChallenge PublicKeyAndChallenge
	SignatureAlgorithm    pkix.AlgorithmIdentifier
	Signature             asn1.BitString
}
