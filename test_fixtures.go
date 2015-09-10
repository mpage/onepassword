package onepassword

import (
	"encoding/base64"
)

// Fixtures taken from Onepassword sample data at:
// https://cache.agilebits.com/security-kb/freddy-2013-12-04.tar.gz

func getValidOPData() ([]byte) {
	b64data := "b3BkYXRhMDEAAQAAAAAAACN8JuE76yN6hbjqzEvd0RGnu3vufP" +
		"cfAZ35JoyzdR1WPRvr8DMefe9MJu65DmHSwjObPC0jznXpafJQ" +
		"ob6CNzKCNoeVC+GXIvLckvAuYUNSwILQQ1jEIcHdyQ0H2MbJ+0" +
		"YlWEbvlQ8UVH5bcrMqDmTPPSRkbUG3/dV1NKHdgI0V6N/kKZ73" +
		"7oo+kj3ChJZQTKywvmR6RgB5et5stBaUwutNQbZ0znYtZumIlf" +
		"3pjdqGK4RyCHSwmwgLUO+VFLTqDjoZ9dUcy4hQzSZiPlba3vK8" +
		"vGJRlN0Qf2Y6dUj5kYAwdYdOzE/Ji3hbTNVsPOm8sjzPcPGQj8" +
		"haW5UgzSDZ0mo7+ymsKJwSYjAsgvawh31WY2m5j7VR+50ERDTE" +
		"yxxQ3LW7WgetAxX9l0LX0O3Jue1oW/p2l44ij9qiN9rkFScx"
	opdata, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		panic("Invalid base64 opdata!")
	}
	return opdata
}
