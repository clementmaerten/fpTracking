package fpTracking

import (
	"time"
	"fmt"
	"strings"
	"crypto/md5"
	"github.com/avct/uasurfer"
)

// Fingerprint data structure
type Fingerprint struct {
	Counter           int
	UserID            string
	AddressHTTP       string
	CreationDate      time.Time
	EndDate           time.Time
	UserAgent         string
	Accept            string
	Connection        string
	Encoding          string
	Language          string
	Order             string
	Plugins           string
	Platform          string
	Cookies           string
	Dnt               string
	Timezone          string
	Resolution        string
	Local             string
	FontsFlash        string
	Vendor            string
	Renderer          string
	PluginsHashed     string
	FontsHashed       string
	fontList          []string
	CanvasHashed      string
	Browser           string
	MajorVersion      int
	MinorVersion      int
	GlobalVersion     string
	OS                string
	ConstantHash      string
	ExactHash         string
	hasFlashActivated bool
}

// InitFingerprint initializes default values in the fingerprint
func (fp *Fingerprint) InitFingerprint() {
	ua := uasurfer.Parse(fp.UserAgent)
	fp.OS = ua.OS.Name.String()
	fp.Browser = ua.Browser.Name.String()
	fp.MajorVersion = ua.Browser.Version.Major
	fp.MinorVersion = ua.Browser.Version.Minor
	fp.GlobalVersion = fmt.Sprintf("%d%d", fp.MajorVersion, fp.MinorVersion)

	constantHashString := []byte(fmt.Sprintf("%s%s%s", fp.OS, fp.Platform, fp.Browser))
	digest := md5.New()
	digest.Write(constantHashString)
	fp.ConstantHash = string(digest.Sum(nil))

	exactHashstring := []byte(fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
		fp.UserAgent, fp.Accept, fp.Connection,
		fp.Encoding, fp.Language, fp.Order, fp.PluginsHashed,
		fp.Platform, fp.Cookies, fp.Dnt, fp.Timezone, fp.Resolution,
		fp.Local, fp.FontsHashed, fp.Vendor, fp.Renderer, fp.CanvasHashed))
	digest = md5.New()
	digest.Write(exactHashstring)
	fp.ExactHash = string(digest.Sum(nil))

	fp.hasFlashActivated = fp.HasFlashActivated()

	if fp.hasFlashActivated {
		fp.fontList = make([]string, 0)
		tmpList := strings.Split(fp.FontsFlash, "_")
		for _, font := range tmpList {
			fp.fontList = append(fp.fontList, font)
		}
	}
}

func (fp *Fingerprint) HasFlashActivated() bool {
	if fp.FontsFlash != "Flash detected but not activated (click-to-play)" &&
		fp.FontsFlash != "Flash not detected" &&
		fp.FontsFlash != "Flash detected but blocked by an extension" {
		return true
	} else {
		return false
	}
}

// A MODIFIER !!!!!!
func stringListIsSubset(list1, list2 []string) bool {
	return true
}

//Returns True if the fonts of the current fingerprint are a subset of another fingerprint fp or the opposite
//Else, it returns False
func (fp1 *Fingerprint) AreFontsSubset(fp2 Fingerprint) bool {
	return stringListIsSubset(fp1.fontList,fp2.fontList) || stringListIsSubset(fp2.fontList,fp1.fontList)
} 