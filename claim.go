package ontchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log"

	jsoniter "github.com/json-iterator/go"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology/common"
	sdk "github.com/vinely/ontchain/ontsdk"
)

var (
	// claimcontract = "80c2b7297b006e5ca8fcd52766453219bc5c4435"
	claimcontract = "36bb5c053b6b839c8f6b923fe852f91239b9fccc"
)

// Claim -
type Claim struct {
	Claim    []byte
	Commiter []byte
	Owner    []byte
}

// GenerateClaim - generate method
func GenerateClaim(d []byte) []byte {
	hash := sha256.Sum256(d)
	return []byte(hex.EncodeToString(hash[:]))
}

// VerifyClaim - verify claim content
func VerifyClaim(claim, data []byte) bool {
	hash := sha256.Sum256(data)
	d := []byte(hex.EncodeToString(hash[:]))
	if bytes.Compare(d, claim) == 0 {
		return true
	}
	return false
}

// MakeClaim - convert data to claim
func MakeClaim(commiter, owner []byte, data interface{}) *Claim {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	d, err := json.Marshal(data)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	claim := GenerateClaim(d)
	return &Claim{
		Claim:    claim,
		Commiter: commiter,
		Owner:    owner,
	}
}

// ClaimCommit - Commit claim
func ClaimCommit(claim *Claim, acct *sdk.Account) (common.Uint256, error) {
	sdk := GetSdk("")
	params := make([]interface{}, 0)
	params = append(params, []byte("Commit"))

	p := []interface{}{
		claim.Claim, claim.Commiter, claim.Owner,
	}
	params = append(params, p)
	addr, _ := common.AddressFromHexString(claimcontract)
	return sdk.NeoVM.InvokeNeoVMContract(0, 20000, acct, addr, params)
}

// ClaimGetStatus -  get claim status
func ClaimGetStatus(claim string) *sdkcom.PreExecResult {
	sdk := GetSdk("")
	params := make([]interface{}, 0)
	params = append(params, []byte("GetStatus"))

	p := []interface{}{
		[]byte(claim),
	}
	params = append(params, p)
	addr, _ := common.AddressFromHexString(claimcontract)
	rest, err := sdk.NeoVM.PreExecInvokeNeoVMContract(addr, params)
	if err != nil {
		log.Println(err)
		return nil
	}
	return rest
}

// ClaimRevoke - revoke a claim
func ClaimRevoke(claim, commiter string, acct *sdk.Account) (common.Uint256, error) {
	sdk := GetSdk("")
	params := make([]interface{}, 0)
	params = append(params, []byte("Revoke"))

	p := []interface{}{
		[]byte(claim), []byte(commiter),
	}
	params = append(params, p)
	addr, _ := common.AddressFromHexString(claimcontract)
	return sdk.NeoVM.InvokeNeoVMContract(0, 20000, acct, addr, params)
}
