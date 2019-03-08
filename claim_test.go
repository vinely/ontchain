package ontchain

import (
	"fmt"
	"testing"
)

func TestMakeClaim(t *testing.T) {
	clm := MakeClaim([]byte("TUG75MexN6BYDNNRcWFWM1fyMpbBQ1dLcW"), []byte("TUG75MexN6BYDNNRcWFWM1fyMpbBQ1dLcW"), "XXXYYY")
	fmt.Printf("claim %s\n", string(clm.Claim))
	fmt.Printf("Owner %s\n", string(clm.Owner))
	fmt.Printf("Commiter %s\n", string(clm.Commiter))
}

func TestClaimCommit(t *testing.T) {
	clm := MakeClaim([]byte("TUG75MexN6BYDNNRcWFWM1fyMpbBQ1dLcW"), []byte("TUG75MexN6BYDNNRcWFWM1fyMpbBQ1dLcW"), "XX1XY2YY")
	w := testCreateWallet()
	acct, _ := w.Wallet.GetDefaultAccount(w.Password)
	h, err := ClaimCommit(clm, acct)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("Hash %s\n", h.ToHexString())
		fmt.Printf("claim %s\n", string(clm.Claim))
		fmt.Printf("Owner %s\n", string(clm.Owner))
		fmt.Printf("Commiter %s\n", string(clm.Commiter))
	}
}

func TestClaimGetStatus(t *testing.T) {
	claim := "e924e3e58011cabffe202fc1c8408179464d4cb43d654f4d68b3a855a0b2342f"
	rest := ClaimGetStatus(claim)
	if rest != nil {
		fmt.Println("ok")
		fmt.Printf("Result :%v\n", rest.Result)
		fmt.Printf("State :%v\n", rest.State)
	}
}

func TestClaimRevoke(t *testing.T) {
	claim := "e924e3e58011cabffe202fc1c8408179464d4cb43d654f4d68b3a855a0b2342f"
	commiter := "TUG75MexN6BYDNNRcWFWM1fyMpbBQ1dLcW"
	w := testCreateWallet()
	acct, _ := w.Wallet.GetDefaultAccount(w.Password)
	h, err := ClaimRevoke(claim, commiter, acct)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("Hash %s\n", h.ToHexString())
		fmt.Printf("claim %s\n", claim)
		fmt.Printf("Commiter %s\n", commiter)
	}
}
