package groupsig

import (
	"log"
	"unsafe"

	"github.com/dfinity/go-bls-crypto/bls"
	"github.com/dfinity/go-bls-crypto/rand"
)

// Signature --
type Signature struct {
	value bls.Sign
}

// IsEqual --
func (sig Signature) IsEqual(rhs Signature) bool {
	return sig.value.IsEqual(&rhs.value)
}

// GetRand --
func (sig Signature) GetRand() rand.Rand {
	return rand.RandFromBytes(sig.Serialize())
}

// Deserialize --
func (sig *Signature) Deserialize(b []byte) error {
	return sig.value.Deserialize(b)
}

// Serialize --
func (sig Signature) Serialize() []byte {
	return sig.value.Serialize()
}

// GetHexString -- return hex string without the 0x prefix
func (sig Signature) GetHexString() string {
	return sig.value.GetHexString()
}

// SetHexString --
func (sig *Signature) SetHexString(s string) error {
	return sig.value.SetHexString(s)
}

// Sign -- sign a message with secret key
func Sign(sec Seckey, msg []byte) (sig Signature) {
	sig.value = *sec.value.Sign(string(msg))
	return sig
}

// VerifySig -- verify message and signature against public key
func VerifySig(pub Pubkey, msg []byte, sig Signature) bool {
	return sig.value.Verify(&pub.value, string(msg))
}

// VerifyAggregateSig --
func VerifyAggregateSig(pubs []Pubkey, msg []byte, asig Signature) bool {
	pub := AggregatePubkeys(pubs)
	if pub == nil {
		return false
	}
	return VerifySig(*pub, msg, asig)
}

// BatchVerify --
func BatchVerify(pubs []Pubkey, msg []byte, sigs []Signature) bool {
	return VerifyAggregateSig(pubs, msg, AggregateSigs(sigs))
}

// AggregateSigs -- aggregate multiple into one by summing up
func AggregateSigs(sigs []Signature) (sig Signature) {
	n := len(sigs)
	if n >= 1 {
		sig.value = sigs[0].value
		for i := 1; i < n; i++ {
			sig.value.Add(&sigs[i].value)
		}
	}
	return sig
}

// RecoverSignature -- Recover master from shares through Lagrange interpolation
func RecoverSignature(sigs []Signature, ids []ID) *Signature {
	signVec := *(*[]bls.Sign)(unsafe.Pointer(&sigs))
	idVec := *(*[]bls.ID)(unsafe.Pointer(&ids))

	sig := new(Signature)
	err := sig.value.Recover(signVec, idVec)
	if err != nil {
		log.Printf("RecoverSignature err=%s\n", err)
		return nil
	}
	return sig
}