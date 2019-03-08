package ontchain

import (
	"fmt"
	"testing"

	"gopkg.in/go-playground/validator.v9"
	// validator "gopkg.in/go-playground/validator.v9"
)

func TestGetIdentity(t *testing.T) {
	id := GetID()
	fmt.Println(id)
}

func TestIdentityFormat(t *testing.T) {
	id := struct {
		ID string `validate:"required,identity"`
	}{
		"TFt7y1hc396kVSemHfcATBEH3NdU9LYffi",
		// "did:ont:TRWtztDFRFNDyJgdsRxeMMp1mffhNpWQM5",
	}
	v := validator.New()
	v.RegisterValidation("identity", IdentityFormat)
	err := v.Struct(id)
	if err != nil {
		t.Error(err)
	}
}

// func TestRegIDWithAttributes(t *testing.T) {
// 	attributes := make([]*sdk.DDOAttribute, 0)
// 	attr1 := &sdk.DDOAttribute{
// 		Key:       []byte("Hello"),
// 		Value:     []byte("World"),
// 		ValueType: []byte("string"),
// 	}
// 	attributes = append(attributes, attr1)
// 	attr2 := &sdk.DDOAttribute{
// 		Key:       []byte("Foo"),
// 		Value:     []byte("Bar"),
// 		ValueType: []byte("string"),
// 	}
// 	attributes = append(attributes, attr2)
// 	RegIDWithAttributes(attributes)
// }

// func TestGetDDO(t *testing.T) {
// 	id := GetDefAccountIdentity()
// 	ddo := GetDDO(id.ID)
// 	fmt.Println(id.ID)
// 	fmt.Printf("owner is %v\n", ddo.Owners)
// 	fmt.Printf("Attribute is %v\n", ddo.Attributes)
// }
