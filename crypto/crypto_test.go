package crypto

import (
	"encoding/json"
	"testing"
)

// Fixtures taken from Onepassword sample data at:
// https://cache.agilebits.com/security-kb/freddy-2013-12-04.tar.gz

const (
	masterPass  = "freddy"
	profileJson = `
{
  "lastUpdatedBy": "Dropbox",
  "updatedAt": 1370323483,
  "profileName": "default",
  "salt": "P0pOMMN6Ow5wIKOOSsaSQg==",
  "masterKey": "b3BkYXRhMDEAAQAAAAAAACN8JuE76yN6hbjqzEvd0RGnu3vufPcfAZ35JoyzdR1WPRvr8DMefe9MJu65DmHSwjObPC0jznXpafJQob6CNzKCNoeVC+GXIvLckvAuYUNSwILQQ1jEIcHdyQ0H2MbJ+0YlWEbvlQ8UVH5bcrMqDmTPPSRkbUG3/dV1NKHdgI0V6N/kKZ737oo+kj3ChJZQTKywvmR6RgB5et5stBaUwutNQbZ0znYtZumIlf3pjdqGK4RyCHSwmwgLUO+VFLTqDjoZ9dUcy4hQzSZiPlba3vK8vGJRlN0Qf2Y6dUj5kYAwdYdOzE/Ji3hbTNVsPOm8sjzPcPGQj8haW5UgzSDZ0mo7+ymsKJwSYjAsgvawh31WY2m5j7VR+50ERDTEyxxQ3LW7WgetAxX9l0LX0O3Jue1oW/p2l44ij9qiN9rkFScx",
  "iterations": 50000,
  "uuid": "2B894A18997C4638BACC55F2D56A4890",
  "overviewKey": "b3BkYXRhMDFAAAAAAAAAAIy1hZwIGeiLn4mLE1R8lEwIOye95GEyfZcPKlyXkkb0IBTfCXM+aDxjD7hOliuTM/YMIqxK+firVvW3c5cp2QMgvQHpDW2AsAQpBqcgBgRUCSP+THMVg15ZeR9lI77mHBpTQ70D+bchvkSmw3hoEGot7YcnQCATbouhMXIMO52D",
  "createdAt": 1373753414
}
`
	itemJson = `
{
  "category": "108",
  "created": 1370129714,
  "d": "b3BkYXRhMDHAAAAAAAAAALKcrmbSK3N10mz8SnKVCpdQS2cYLptNG47UL3OT3kJ3HFTlnEZUlC+RgPGWt1ZTSiC+vGBFMIltHU3o1sJ/LxO7k8nSuX3Iky4BadclqAur8ux/kH2TyfBdWTu+sRSskE5tMb3SB0z3Yfv+w5nj3c7amD2eClrxwFyjW/Jv1reHAI4p3HD9bbDxVlVxHFuqsVlwsb8fiAdIXmhtf1ZQv8XM+Vd1KBSHaKC/nVcwyG/ZS0r4CyGdiQUq2bEvdERssRR1nzjT+g/sFseD8q4jrXVXhezXQdstl81GM3WSvVSm5lT/z6qMbCUrcPW7AZsFIcAMqtRHexBvKwfjpn3Tj5M=",
  "hmac": "AVY2ZVXViuYtgfnSKShK/ZbbVn6T9SMfugz7F89Kd2Q=",
  "k": "NwsqfULiH/XRz0LPCNJ5u1Kv4Onmqmeu1Ye4UKmipo6YspWDQ9zswlSWqgtjhKVzsv+eq9G6qQftYwG4cHbid18RdZksQWqDCrnE7arx9zwR9mYdxB9Eymb/nSU4o03D9pkAk/niM23vS7qkbbap8A==",
  "o": "b3BkYXRhMDE8AAAAAAAAAPnQNt3DIzXvm/rjmdk/NHmfWLgOs+/hvM6nFutXkkSPcWK2Xl9NAzyoMV86XJviJF2wYd74eJFXZgFDgflquGnrK6xQifFqMj6zxVF4r6EACcNtzHgsrv054MFtKKiZm073KEQStDhnI2dwtRWQQjM=",
  "tx": 1373753420,
  "updated": 1370129765,
  "uuid": "67979020CCA54120BAFA2742C3F23F2B"
}
`
	decryptedItemDetails = `{"sections":[{"name":"","title":"","fields":[{"k":"string","n":"name","v":"Wendy Appleseed","t":"name"},{"k":"concealed","v":"555-55-1234","n":"number","a":{"generate":"off"},"t":"number"}]}]}`
)

type profile struct {
	Salt       []byte `json:"salt"`
	MasterKey  []byte `json:"masterKey"`
	Iterations int    `json:"iterations"`
}

type item struct {
	Details   []byte `json:"d"`
	Key       []byte `json:"k"`
	HMAC      []byte `json:"hmac"`
}

func profileFixture() (*profile) {
	var p profile
	err := json.Unmarshal([]byte(profileJson), &p)
	if err != nil {
		panic("Failed decoding profile json")
	}
	return &p
}

func itemFixture() (*item) {
	var i item
	err := json.Unmarshal([]byte(itemJson), &i)
	if err != nil {
		panic("Failed decoding item json")
	}
	return &i
}

func TestDecryptMasterKey(t *testing.T) {
	profile := profileFixture()
	derKP := ComputeDerivedKeys(masterPass, profile.Salt, profile.Iterations)

	// Get the master item keys
	masterKP, err := DecryptMasterKeys(profile.MasterKey, derKP)
	if err != nil {
		t.Fatalf("Failed decrypting master item keys: %s", err.Error())
	}

	// Get the item key
	item := itemFixture()
	itemKP, err := DecryptItemKey(item.Key, masterKP)
	if err != nil {
		t.Fatalf("Failed decrypting item keys: %s", err.Error())
	}

	// Get details
	details, err := DecryptOPData01(item.Details, itemKP)
	if err != nil {
		t.Fatalf("Failed decrypting details: %s", err.Error())
	} else if string(details) != decryptedItemDetails {
		t.Fatalf("Unexpected details returned. Expected '%s'. Got '%s'.", decryptedItemDetails, details)
	}

}
