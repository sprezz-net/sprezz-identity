package model

// ResolvedAssurance encapsulates the finalized numeric assurance rankings
// computed natively during an authentication session life cycle [1.1].
type ResolvedAssurance struct {
	AAL int `json:"aal"`
	IAL int `json:"ial"`
}
