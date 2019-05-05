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
	sdk.IdentityData
	Password []byte
}

// GetIdentityFromID - get identity struct from id include control data
func GetIdentityFromID(id string, passwd []byte) (*ManagedIdentity, error) {
	identity, err := sdk.GetDefaultIdentityFromID(id, passwd)
	if err != nil {
		return nil, err
	}
	return &ManagedIdentity{*identity.ToIdentityData(), passwd}, nil
}

// Identity - get identity from managedidentity
func (id *ManagedIdentity) Identity() (*sdk.Identity, error) {
	return sdk.NewIdentityFromIdentityData(&id.IdentityData)
}

// RegisterID - register id to blockchain
func (id *ManagedIdentity) RegisterID(signer *sdk.Account) {
	s := GetSdk("")
	// ctl, err := id.NewController("2", keypair.PK_ECDSA, keypair.P256, s.SHA256withECDSA, password)
	i, err := id.Identity()
	if err != nil {
		log.Fatal(err)
		return
	}
	ctl, err := i.GetControllerByIndex(1, id.Password)
	if err != nil {
		log.Fatal(err)
		return
	}
	_, err = s.Native.OntID.RegIDWithPublicKey(0, 20000, signer, id.ID, ctl)
	if err != nil {
		log.Fatal(err)
		return
	}
}

// RegIDWithAttributes -register id with attributes
func (id *ManagedIdentity) RegIDWithAttributes(attr map[string]string, signer *sdk.Account) {
	s := GetSdk("")
	// ctl, err := id.NewController("2", keypair.PK_ECDSA, keypair.P256, s.SHA256withECDSA, password)
	i, err := id.Identity()
	if err != nil {
		log.Fatal(err)
		return
	}
	ctl, err := i.GetControllerByIndex(1, id.Password)
	if err != nil {
		log.Fatal(err)
		return
	}
	attributes := StringMap2Attributes(attr)
	_, err = s.Native.OntID.RegIDWithAttributes(0, 20000, signer, id.ID, ctl, attributes)
	if err != nil {
		log.Fatal(err)
		return
	}
}

// Attributes2StringMaps - attributes to map
func Attributes2StringMaps(attributes []*sdk.DDOAttribute) map[string]string {
	l := len(attributes)
	if l <= 0 {
		return nil
	}
	result := make(map[string]string, l)
	for _, v := range attributes {
		result[string(v.Key)] = string(v.Value)
	}
	return result
}

// StringMap2Attributes - stringmap to attributes
func StringMap2Attributes(attr map[string]string) []*sdk.DDOAttribute {
	l := len(attr)
	if l <= 0 {
		return nil
	}
	result := []*sdk.DDOAttribute{}
	for k := range attr {
		result = append(result, &sdk.DDOAttribute{
			Key:       []byte(k),
			ValueType: []byte("string"),
			Value:     []byte(attr[k]),
		})
	}
	return result
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
