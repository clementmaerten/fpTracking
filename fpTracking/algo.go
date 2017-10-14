package fpTracking

import (
	"bufio"
	"crypto/md5"
	"database/sql"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/avct/uasurfer"
	uuid "github.com/satori/go.uuid"
	"github.com/xrash/smetrics"
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

	if fp.FontsFlash != "Flash detected but not activated (click-to-play)" &&
		fp.FontsFlash != "Flash not detected" &&
		fp.FontsFlash != "Flash detected but blocked by an extension" {
		fp.hasFlashActivated = true
	} else {
		fp.hasFlashActivated = false
	}

	if fp.hasFlashActivated {
		fp.fontList = make([]string, 0)
		tmpList := strings.Split(fp.FontsFlash, "_")
		for _, font := range tmpList {
			fp.fontList = append(fp.fontList, font)
		}
	}
}


// FingerprintManager manages the obtention of fingerprints
type FingerprintManager struct {
	Number int
	Train  float64
}

// GetFingerprints returns two slices train, test of Fingerprint structs
func (fm FingerprintManager) GetFingerprints() ([]Fingerprint, []Fingerprint) {
	db, _ := sql.Open("mysql", "root:bdd@/canvas_fp_project?parseTime=true")
	defer db.Close()

	file, _ := os.Open("./data/consistent_extension_ids.csv")
	defer file.Close()

	scanner := bufio.NewScanner(file)
	consistentIDs := []string{"'"}
	for scanner.Scan() {
		consistentIDs = append(consistentIDs, scanner.Text())
	}
	consistentIDs = append(consistentIDs, "'")
	consistentIDsQuery := strings.Join(consistentIDs, "','")

	fingerprints := make([]Fingerprint, 0)
	trainFingerprints := make([]Fingerprint, 0)
	testFingerprints := make([]Fingerprint, 0)

	stmt, err := db.Prepare(`SELECT counter, id, addressHttp, creationdate, endDate,
									userAgentHttp, acceptHttp, connectionHttp, 
									encodingHttp, languageHttp, orderHttp,
									pluginsJS, platformJS, cookiesJS, dntJS,
									timezoneJS, resolutionJS, localJS,
									fontsFlash, vendorWebGLJS, rendererWebGLJS,
									pluginsJSHashed, fontsFlashHashed, canvasJSHashed
									FROM extensionData WHERE counter < ? AND
									creationDate IS NOT NULL AND
									endDate IS NOT NULL AND char_length(id) > 15
									AND id in (` + consistentIDsQuery + `) AND id in
									(SELECT id FROM extensionData group by id having count(*) > 6) order by counter`)

	if err != nil {
		panic(err.Error()) // proper error handling instead of panic in your app
	}
	defer stmt.Close()

	rows, err := stmt.Query(fm.Number)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var counter int
	var id, addressHTTP, userAgentHTTP, acceptHTTP, connectionHTTP string
	var encodingHTTP, languageHTTP, orderHTTP, pluginsJS, platformJS string
	var cookiesJS, dntJS, timezoneJS, resolutionsJS, localJS, fontsFlash string
	var vendor, renderer, pluginsJSHashed, fontsFlashHashed, canvasJSHashed string
	var creationDate, endDate time.Time

	cpt := 0
	var nbTrain, nbTest int
	for rows.Next() {
		err := rows.Scan(&counter, &id, &addressHTTP, &creationDate, &endDate, &userAgentHTTP,
			&acceptHTTP, &connectionHTTP, &encodingHTTP, &languageHTTP, &orderHTTP, &pluginsJS,
			&platformJS, &cookiesJS, &dntJS, &timezoneJS, &resolutionsJS, &localJS,
			&fontsFlash, &vendor, &renderer, &pluginsJSHashed, &fontsFlashHashed, &canvasJSHashed)

		if err != nil {
			log.Fatal(err)
		}

		fp := Fingerprint{
			Counter:       counter,
			UserID:        id,
			AddressHTTP:   addressHTTP,
			CreationDate:  creationDate,
			EndDate:       endDate,
			UserAgent:     userAgentHTTP,
			Accept:        acceptHTTP,
			Connection:    connectionHTTP,
			Encoding:      encodingHTTP,
			Language:      languageHTTP,
			Order:         orderHTTP,
			Plugins:       pluginsJS,
			Platform:      platformJS,
			Cookies:       cookiesJS,
			Dnt:           dntJS,
			Timezone:      timezoneJS,
			Resolution:    resolutionsJS,
			Local:         localJS,
			FontsFlash:    fontsFlash,
			Vendor:        vendor,
			Renderer:      renderer,
			PluginsHashed: pluginsJSHashed,
			FontsHashed:   fontsFlashHashed}

		fp.InitFingerprint()

		fingerprints = append(fingerprints, fp)
		cpt++

	}

	nbTrain = int(math.Ceil(fm.Train * float64(cpt)))
	nbTest = cpt - nbTest

	for i := 0; i < nbTrain; i++ {
		trainFingerprints = append(trainFingerprints, fingerprints[i])
	}

	for i := nbTrain; i < cpt; i++ {
		testFingerprints = append(testFingerprints, fingerprints[i])
	}

	return trainFingerprints, testFingerprints
}

type ScenarioResult struct {
	counterStr string
	assignedID string
}

type sequenceElt struct {
	counterStr string
	counter    int
	lastVisit  time.Time
}

func generateReplaySequence(fingerprintDataset []Fingerprint, visitFrequency int) []sequenceElt {
	userIDToFingerprints := make(map[string][]Fingerprint)
	for _, fingerprint := range fingerprintDataset {
		userIDToFingerprints[fingerprint.UserID] = append(userIDToFingerprints[fingerprint.UserID], fingerprint)
	}
	userIDToSequence := make(map[string][]sequenceElt)

	for userID := range userIDToFingerprints {
		// fmt.Printf("user id: %s\n", userID)
		if len(userIDToFingerprints[userID]) > 1 {
			sequence := make([]sequenceElt, 0)
			lastVisit := userIDToFingerprints[userID][0].CreationDate
			counterSuffix := "i"
			assignedCounter := fmt.Sprintf("%d_%s", userIDToFingerprints[userID][0].Counter, counterSuffix)
			// fmt.Printf("assignedCounter %s\n", assignedCounter)
			sequence = append(sequence, sequenceElt{counterStr: assignedCounter,
				lastVisit: lastVisit,
				counter:   userIDToFingerprints[userID][0].Counter})

			for i := 0; i < len(userIDToFingerprints[userID])-1; i++ {
				fingerprint := userIDToFingerprints[userID][i]
				counterSuffixInt := 0

				for lastVisit.AddDate(0, 0, visitFrequency).Sub(fingerprint.EndDate) < 0 {
					lastVisit = lastVisit.AddDate(0, 0, visitFrequency)
					assignedCounter = fmt.Sprintf("%d_%d", fingerprint.Counter, counterSuffixInt)
					// fmt.Printf("assignedCounter %s\n", assignedCounter)
					sequence = append(sequence, sequenceElt{counterStr: assignedCounter,
						lastVisit: lastVisit,
						counter:   fingerprint.Counter})
					counterSuffixInt++
				}
			}
			userIDToSequence[userID] = sequence
		}
	}

	replaySequence := make([]sequenceElt, 0)
	for _, sequences := range userIDToSequence {
		for _, sequence := range sequences {
			replaySequence = append(replaySequence, sequence)
		}
	}

	// for _, sequence := range replaySequence {
	// fmt.Printf("rep seq: %s", sequence.counterStr)
	// }

	sort.Slice(replaySequence, func(i, j int) bool {
		return replaySequence[i].lastVisit.Sub(replaySequence[j].lastVisit) < 0
	})

	return replaySequence
}
