package groupsig

// Pop --
type Pop Signature

// GeneratePop
func GeneratePop(sec Seckey, pub Pubkey) Pop {
	return Pop(Sign(sec, pub.Serialize()))
}

// VerifyPop
func VerifyPop(pub Pubkey, pop Pop) bool {
	return VerifySig(pub, pub.Serialize(), Signature(pop))
}