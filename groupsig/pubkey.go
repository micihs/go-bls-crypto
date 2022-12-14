package groupsig

import (
	"log"
	"unsafe"

	"github.com/dfinity/go-dfinity-crypto/bls"
)

type Pubkey struct {
	value bls.PublicKey
}


func (pub Pubkey) IsEqual(rhs Pubkey) bool {
	return pub.value.IsEqual(&rhs.value)
}

func (pub *Pubkey) Deserialize(b []byte) error {
	return pub.value.Deserialize(b)
}


func (pub Pubkey) Serialize() []byte {
	return pub.value.Serialize()
}

func (pub Pubkey) GetHexString() string {
	return pub.value.GetHexString()
}

func (pub *Pubkey) SetHexString(s string) error {
	return pub.value.SetHexString(s)
}

func NewPubkeyFromSeckey(sec Seckey) *Pubkey {
	pub := new(Pubkey)
	pub.value = *sec.value.GetPublicKey()
	return pub
}

func TrivialPubkey() *Pubkey {
	return NewPubkeyFromSeckey(*TrivialSeckey())
}

func AggregatePubkeys(pubs []Pubkey) *Pubkey {
	if len(pubs) == 0 {
		log.Printf("AggregatePubkeys no pubs")
		return nil
	}
	pub := new(Pubkey)
	pub.value = pubs[0].value
	for i := 1; i < len(pubs); i++ {
		pub.value.Add(&pubs[i].value)
	}
	return pub
}

func SharePubkey(mpub []Pubkey, id ID) *Pubkey {
	mpk := *(*[]bls.PublicKey)(unsafe.Pointer(&mpub))
	pub := new(Pubkey)
	err := pub.value.Set(mpk, &id.value)
	if err != nil {
		log.Printf("SharePubkey err=%s id=%s\n", err, id.GetHexString())
		return nil
	}
	return pub
}

func SharePubkeyByInt(mpub []Pubkey, i int) *Pubkey {
	return SharePubkey(mpub, *NewIDFromInt(i))
}

func SharePubkeyByMembershipNumber(mpub []Pubkey, id int) *Pubkey {
	return SharePubkey(mpub, *NewIDFromInt(id + 1))
}