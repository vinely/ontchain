package ontchain

import (
	"log"
	"strings"

	sdk "github.com/vinely/ontchain/ontsdk"

	validator "gopkg.in/go-playground/validator.v9"
)

// GetID - just generate ID
func GetID() string {
	id, err := sdk.GenerateID()
	if err != nil {
		log.Fatal(err)
	}
	return id
}

// IdentityFormat - validate for indentity
func IdentityFormat(fl validator.FieldLevel) bool {
	str := fl.Field().String()
	if strings.HasPrefix(str, "did:ont:") {
		return sdk.VerifyID(str)
	}
	return sdk.VerifyID("did:ont:" + str)
}

// ManagedIdentity - Get Password in storage
type ManagedIdentity struct {
	sdk.Identity
	Password []byte
}

// GetIdentityFromID - get identity struct from id include control data
func GetIdentityFromID(id string, passwd []byte) (*ManagedIdentity, error) {
	identity, err := sdk.GetDefaultIdentityFromID(id, passwd)
	if err != nil {
		return nil, err
	}
	return &ManagedIdentity{*identity, passwd}, nil
}

// RegIDWithAttributes -register id with attributes
func RegIDWithAttributes(id *ManagedIdentity, attributes []*sdk.DDOAttribute, signer *sdk.Account) {
	sdk := GetSdk("")
	// ctl, err := id.NewController("2", keypair.PK_ECDSA, keypair.P256, s.SHA256withECDSA, password)
	ctl, err := id.GetControllerByIndex(1, id.Password)
	if err != nil {
		log.Fatal(err)
		return
	}
	_, err = sdk.Native.OntID.RegIDWithAttributes(0, 20000, signer, id.ID, ctl, attributes)
	if err != nil {
		log.Fatal(err)
		return
	}
}

// GetDDO - get ddo by id
func GetDDO(id string) *sdk.DDO {
	sdk := GetSdk("")
	// sdk.WaitForGenerateBlock(30*time.Second, 1)
	ddo, err := sdk.Native.OntID.GetDDO(id)
	if err != nil {
		log.Fatalf("GetDDO error:%s", err)
		return nil
	}
	return ddo
}
